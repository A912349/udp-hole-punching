package main

import (
	"encoding/json"
	"io"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"
)
func (n *node) sendHello(p peer) {
	packet := protocol.NewPacket("HELLO", n.id.ID, p.ID, map[string]any{"public_key": n.id.Public})
	if observed, ok := p.last.(*net.UDPAddr); ok {
		n.sendToAddress(packet, observed)
	}
	// Edge retries are the recovery path: always also try the declared public
	// endpoint. LAN preference and sameNAT are hints, never a reason to
	// withhold a candidate here — the LAN segment may be unreachable even when
	// both nodes share one external IP.
	if address, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
		n.sendToAddress(packet, address)
	}
}
func (n *node) networkFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		n.debugf("network fingerprint unavailable: %v", err)
		return ""
	}
	return fingerprintInterfaces(ifaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }, n.c.tun)
}
func fingerprintInterfaces(ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error), skip string) string {
	parts := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == skip {
			continue
		}
		list, err := addrs(iface)
		if err != nil {
			continue
		}
		addresses := make([]string, 0, len(list))
		for _, address := range list {
			prefix, ok := address.(*net.IPNet)
			if !ok || prefix.IP.To4() == nil {
				continue
			}
			ones, _ := prefix.Mask.Size()
			addresses = append(addresses, prefix.IP.String()+"/"+strconv.Itoa(ones))
		}
		if len(addresses) == 0 {
			continue
		}
		sort.Strings(addresses)
		parts = append(parts, iface.Name+"="+strings.Join(addresses, ","))
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}
func (n *node) monitorNetwork(ctx context.Context) {
	previous := n.networkFingerprint()
	ticker := time.NewTicker(networkCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := n.networkFingerprint()
		// An empty fingerprint means "cannot tell" (total loss, enumeration
		// failure); only a real observed change triggers roaming recovery.
		if current == "" || current == previous {
			continue
		}
		previous = current
		n.logf("network change detected: %s", current)
		n.handleNetworkChange()
	}
}
func (n *node) handleNetworkChange() {
	// A fresh network event restarts recovery from scratch. Backoff collected
	// while the old network was settling must not delay recovery now that the
	// new network is up. TryLock: when a recovery pass is already running it
	// will pick the new network up on its own.
	if n.recoveryMu.TryLock() {
		n.recoveryFails = 0
		n.recoveryNext = time.Time{}
		n.recoveryMu.Unlock()
	}
	// The control WebSocket rides on the previous network and may stay
	// half-open for minutes. Close it so the next heartbeat reconnects over
	// the new network immediately; readControl will also notice and poke.
	n.controlMu.Lock()
	if n.control != nil {
		_ = n.control.Close()
		n.control = nil
	}
	n.controlMu.Unlock()
	// Coalesce interface flapping into one refresh.
	now := time.Now().Unix()
	last := n.roamRefreshAt.Load()
	if last != 0 && time.Since(time.Unix(last, 0)) < roamRefreshMinGap {
		return
	}
	if !n.roamRefreshAt.CompareAndSwap(last, now) {
		return
	}
	go n.roamRefresh(1)
}
func (n *node) detectEndpoint() (string, string, error) {
	n.udpReadMu.Lock()
	defer n.udpReadMu.Unlock()
	return stunEndpoint(n.currentUDPConn(), n.handleDatagram, n.c.bootstrapDNS...)
}
func (n *node) helloAll() {
	n.mu.RLock()
	type helloTarget struct {
		id           string
		observed     *net.UDPAddr
		declared     string
		skipDeclared bool
	}
	targets := make([]helloTarget, 0, len(n.neighbors))
	for id, peer := range n.neighbors {
		// PING/PONG already maintains healthy paths and learns rebinding.
		// HELLO is still sent on startup, to stale peers and by edge retries.
		if n.usable(peer) {
			continue
		}
		target := helloTarget{id: id, declared: peer.Endpoint}
		if address, ok := peer.last.(*net.UDPAddr); ok {
			target.observed = &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
		}
		if freshLAN(peer, time.Now()) && n.sameNAT(peer) {
			// The LAN path is confirmed working (traffic received) and both
			// nodes share one external IP: a duplicate HELLO to the declared
			// public endpoint would only hairpin through the NAT device.
			target.skipDeclared = true
		}
		targets = append(targets, target)
	}
	n.mu.RUnlock()
	for _, target := range targets {
		packet := protocol.NewPacket("HELLO", n.id.ID, target.id, map[string]any{"public_key": n.id.Public})
		if target.observed != nil {
			n.sendToAddress(packet, target.observed)
		}
		if address, err := net.ResolveUDPAddr("udp", target.declared); err == nil &&
			!target.skipDeclared &&
			(target.observed == nil || address.String() != target.observed.String()) {
			n.sendToAddress(packet, address)
		}
	}
}
func (n *node) pingAll() {
	now := time.Now()
	n.mu.RLock()
	targets := make([]pingTarget, 0, len(n.neighbors))
	for id, peer := range n.neighbors {
		target := pingTarget{id: id, endpoint: peer.Endpoint}
		if observed, ok := peer.last.(*net.UDPAddr); ok {
			target.observed = &net.UDPAddr{IP: append(net.IP(nil), observed.IP...), Port: observed.Port, Zone: observed.Zone}
		}
		if lan := peer.lastLAN; lan != nil && !freshLAN(peer, now) {
			// Unconfirmed LAN candidate: keepalives double as LAN probes so a
			// lost broadcast or HELLO costs one keepalive interval instead of
			// the full 30-second probe round. When the LAN path is already
			// traffic-confirmed, observed is the LAN address and no duplicate
			// datagram is sent.
			target.lan = copyUDPAddr(lan)
		}
		targets = append(targets, target)
	}
	n.mu.RUnlock()
	n.pingMu.Lock()
	lost := prunePings(n.pings, now.Add(-linkTimeout))
	n.pingMu.Unlock()
	n.noteLostProbes(lost)
	for _, target := range targets {
		p := protocol.NewPacket("PING", n.id.ID, target.id, map[string]any{})
		if target.lan != nil && (target.observed == nil || target.lan.String() != target.observed.String()) {
			n.sendDirect(p, "", target.lan)
		}
		if !n.sendDirect(p, target.endpoint, target.observed) {
			// Do not wait for the next linkHealth tick when the socket cannot
			// even send the probe. This used to leave a dead edge without any
			// retry until another, unrelated state transition occurred.
			n.mu.RLock()
			current := n.neighbors[target.id]
			var snapshot peer
			if current != nil {
				snapshot = *current
			}
			n.mu.RUnlock()
			if current != nil {
				n.retryDeadEdge(target.id, snapshot)
			}
			continue
		}
		n.pingMu.Lock()
		n.pings[p.ID] = pingProbe{sent: now, peerID: target.id}
		n.pingMu.Unlock()
	}
}
func (n *node) sendDirect(packet protocol.Packet, endpoint string, observed *net.UDPAddr) bool {
	address := observed
	if address == nil {
		var err error
		address, err = net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return false
		}
	}
	// Keepalives use the ~70-byte binary format; anything else (or a compact
	// encoding failure) falls back to the JSON envelope.
	encoded, err := protocol.EncodeCompact(packet, n.key)
	if err != nil {
		if encoded, err = protocol.EncodePacket(packet, n.key); err != nil {
			return false
		}
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return false
	}
	_, err = conn.WriteToUDP(encoded, address)
	return err == nil
}
func prunePings(pings map[string]pingProbe, before time.Time) []string {
	var lost []string
	for id, probe := range pings {
		if probe.sent.Before(before) {
			delete(pings, id)
			lost = append(lost, probe.peerID)
		}
	}
	return lost
}
func (n *node) noteLostProbes(ids []string) {
	if len(ids) == 0 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, id := range ids {
		if p := n.neighbors[id]; p != nil {
			p.lossEMA = p.lossEMA*lossProbeRecover + lossProbePenalty
		}
	}
}
func (n *node) currentLinks() []protocol.LinkMeasurement {
	n.mu.RLock()
	links := make([]protocol.LinkMeasurement, 0, len(n.neighbors))
	for id, p := range n.neighbors {
		links = append(links, protocol.LinkMeasurement{PeerID: id, RTTMS: p.rttMS, Loss: p.lossEMA, Up: !p.lastRX.IsZero() && time.Since(p.lastRX) < linkTimeout, ViaLAN: p.lastPathLAN})
	}
	n.mu.RUnlock()
	return links
}
func (n *node) reportTelemetry() error {
	links := n.currentLinks()
	n.telemetryMu.Lock()
	send := telemetryChanged(n.lastTelemetryLinks, links) || time.Since(n.lastTelemetrySent) >= telemetryKeepalive
	if send {
		n.lastTelemetryLinks = links
		n.lastTelemetrySent = time.Now()
	}
	n.telemetryMu.Unlock()
	if !send {
		return nil
	}
	return n.request("POST", "/v1/telemetry", map[string]any{"node_id": n.id.ID, "links": links}, &map[string]any{})
}
func telemetryChanged(sent, links []protocol.LinkMeasurement) bool {
	if len(sent) != len(links) {
		return true
	}
	previous := make(map[string]protocol.LinkMeasurement, len(sent))
	for _, l := range sent {
		previous[l.PeerID] = l
	}
	for _, l := range links {
		old, ok := previous[l.PeerID]
		if !ok || old.Up != l.Up || old.ViaLAN != l.ViaLAN || lossDrifted(old.Loss, l.Loss) || rttDrifted(old.RTTMS, l.RTTMS) {
			return true
		}
	}
	return false
}
func lossDrifted(prev, next float64) bool {
	return math.Abs(prev-next) >= 0.1
}
func rttDrifted(prev, next float64) bool {
	if prev == 0 || next == 0 {
		return prev != next
	}
	diff := math.Abs(prev - next)
	return diff > 3 && diff > 0.3*math.Max(prev, next)
}
func (n *node) usable(p *peer) bool {
	// A topology entry is only a candidate endpoint. Do not report or route
	// through it until this node has actually received traffic from the peer.
	// Treating a zero lastRX as usable made one side show link up immediately
	// while the other side was still establishing the UDP path.
	return p != nil && !p.lastRX.IsZero() && time.Since(p.lastRX) < linkTimeout
}
func (n *node) send(p protocol.Packet) bool {
	hop, q := n.nextHop(p.Destination)
	if !n.usable(q) {
		// The primary hop is unusable: try the precomputed alternate path
		// while route recomputation catches up, instead of dropping.
		hop, q = n.fallbackHop(p.Destination)
		if !n.usable(q) {
			return false
		}
	}
	a := q.last
	if a == nil {
		var e error
		a, e = net.ResolveUDPAddr("udp", q.Endpoint)
		if e != nil {
			return false
		}
	}
	b, e := n.encodePacketForPeer(p)
	if e != nil {
		return false
	}
	_, e = n.connForPeer(hop).WriteToUDP(b, a.(*net.UDPAddr))
	return e == nil
}
func (n *node) nextHop(destination string) (string, *peer) {
	// Routes can change while packets are in flight; validate a cached peer before using it.
	n.mu.RLock()
	hop := n.routes[destination]
	previousHop := hop
	peer := n.neighbors[hop]
	if n.usable(peer) {
		n.mu.RUnlock()
		return hop, peer
	}
	// Without a usable cached hop every data packet would re-run Dijkstra here.
	// During an outage with traffic flowing that is a CPU storm on a mutex-held
	// path; bound full recomputations to a few per second. Release the read lock
	// before computing so a concurrent writer (topology refresh, link-health tick)
	// parking on n.mu does not hold this traversal hostage — every send on the
	// failed hop would otherwise serialize behind one Dijkstra run.
	n.mu.RUnlock()
	last := n.routeRecompute.Load()
	if time.Since(time.Unix(0, last)) < 250*time.Millisecond {
		return "", nil
	}
	// Claim the recompute window atomically so only one worker runs Dijkstra per
	// window instead of every sender recomputing the same table.
	if !n.routeRecompute.CompareAndSwap(last, time.Now().UnixNano()) {
		return "", nil
	}
	routes, fallbacks := n.computeRoutes()
	n.mu.Lock()
	n.routes = routes
	n.altRoutes = fallbacks
	n.mu.Unlock()
	hop = routes[destination]
	peer = n.neighbors[hop]
	if !n.usable(peer) {
		return "", nil
	}
	if previousHop != hop {
		n.logf("route failover %s -> %s", destination[:8], hop[:8])
	}
	return hop, peer
}
func (n *node) fallbackHop(destination string) (string, *peer) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	hop := n.altRoutes[destination]
	return hop, n.neighbors[hop]
}
func (n *node) startFastWorkers(ctx context.Context) {
	workers := n.c.fastWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		workers = min(workers, 2)
	}
	workers = min(workers, 16)
	n.fastQueue = make(chan fastFrame, fastQueueSize)
	n.fastPool.New = func() any { return make([]byte, maxFastFrame) }
	for range workers {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case frame, ok := <-n.fastQueue:
					if !ok {
						return
					}
					n.fast(frame.data, frame.addr)
					n.fastPool.Put(frame.data[:maxFastFrame])
				}
			}
		}()
	}
}
func (n *node) startDeliverWorker(ctx context.Context) {
	workers := n.c.deliverWorkers
	if workers <= 0 {
		// A TUN device is a single file descriptor; one default writer avoids scheduler and kernel-lock contention.
		workers = 1
	}
	workers = max(1, min(workers, 16))
	n.deliverQueues = make([]chan deliverFrame, workers)
	n.deliverPool.New = func() any { return make([]byte, maxTUN) }
	for i := range n.deliverQueues {
		queue := make(chan deliverFrame, fastQueueSize/workers)
		n.deliverQueues[i] = queue
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case frame := <-queue:
					n.deliver(frame.source, frame.data)
					n.deliverPool.Put(frame.data[:maxTUN])
					// Keep per-socket/TUN ordering while draining work already queued.
					// This avoids returning to select (and an unnecessary scheduler
					// decision) for every packet during a receive burst.
					for i := 0; i < 15; i++ {
						select {
						case frame := <-queue:
							n.deliver(frame.source, frame.data)
							n.deliverPool.Put(frame.data[:maxTUN])
						default:
							i = 15
						}
					}
				}
			}
		}()
	}
}
func (n *node) enqueueDeliver(source string, data []byte) {
	if len(n.deliverQueues) == 0 || len(data) < 20 || len(data) > maxTUN {
		n.stats.deliveryDrops.Add(1)
		return
	}
	// Keep packets from one IPv4 flow on one worker. This permits parallel TUN
	// writes without reordering TCP/UDP packets within a flow.
	flow := uint32(data[9])
	for _, b := range data[12:20] {
		flow = flow*16777619 ^ uint32(b)
	}
	ihl := int(data[0]&15) * 4
	if ihl >= 20 && len(data) >= ihl+4 && (data[9] == 6 || data[9] == 17) {
		for _, b := range data[ihl : ihl+4] {
			flow = flow*16777619 ^ uint32(b)
		}
	}
	queue := n.deliverQueues[int(flow%uint32(len(n.deliverQueues)))]
	owned := n.deliverPool.Get().([]byte)[:len(data)]
	copy(owned, data)
	select {
	case queue <- deliverFrame{source: source, data: owned}:
	default:
		n.deliverPool.Put(owned[:maxTUN])
		n.stats.deliveryDrops.Add(1)
		n.debugf("drop IP packet from %s: TUN queue full", source[:8])
	}
}
func (n *node) deliverQueueUsage() (length, capacity int) {
	for _, queue := range n.deliverQueues {
		length += len(queue)
		capacity += cap(queue)
	}
	return
}
func (n *node) startPprof() error {
	if n.c.pprofListen == "" {
		return nil
	}
	// Enable contention profiles only for diagnostic runs. These profiles are
	// empty by default and are intentionally not enabled in normal operation.
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	host, _, err := net.SplitHostPort(n.c.pprofListen)
	if err != nil {
		return fmt.Errorf("invalid --pprof-listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("--pprof-listen must use localhost or a loopback IP")
	}
	go func() {
		n.logf("pprof available at http://%s/debug/pprof/", n.c.pprofListen)
		if err := http.ListenAndServe(n.c.pprofListen, nil); err != nil {
			n.logf("pprof listener stopped: %v", err)
		}
	}()
	return nil
}
func (n *node) statsLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var previous fastStatsSnapshot
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := n.fastStatsSnapshot()
			rxPackets := current.receivedPackets - previous.receivedPackets
			rxBytes := current.receivedBytes - previous.receivedBytes
			txPackets := current.sentPackets - previous.sentPackets
			txBytes := current.sentBytes - previous.sentBytes
			drops := current.queueDrops - previous.queueDrops
			rxDrops := current.rxQueueDrops - previous.rxQueueDrops
			txDrops := current.txQueueDrops - previous.txQueueDrops
			tunDrops := current.deliveryDrops - previous.deliveryDrops
			controlRxPackets := current.controlRxPackets - previous.controlRxPackets
			controlRxBytes := current.controlRxBytes - previous.controlRxBytes
			controlTxPackets := current.controlTxPackets - previous.controlTxPackets
			controlTxBytes := current.controlTxBytes - previous.controlTxBytes
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			seconds := interval.Seconds()
			deliverLength, deliverCapacity := n.deliverQueueUsage()
			n.logf("stats %s: data rx=%.0f pps %.2f Mbps tx=%.0f pps %.2f Mbps control rx=%.0f pps %.2f Mbps tx=%.0f pps %.2f Mbps tun=%.0f pps queues=%d/%d,%d/%d drops=%d/%d udpTxQueue=%d/%d rxDrops=%d txDrops=%d heap=%.1f MiB goroutines=%d",
				interval, float64(rxPackets)/seconds, float64(rxBytes*8)/seconds/1e6,
				float64(txPackets)/seconds, float64(txBytes*8)/seconds/1e6,
				float64(controlRxPackets)/seconds, float64(controlRxBytes*8)/seconds/1e6,
				float64(controlTxPackets)/seconds, float64(controlTxBytes*8)/seconds/1e6,
				float64(current.deliveredPackets-previous.deliveredPackets)/seconds, len(n.fastQueue), cap(n.fastQueue), deliverLength, deliverCapacity, drops, tunDrops, len(n.udpSendQueue), cap(n.udpSendQueue), rxDrops, txDrops,
				float64(mem.HeapAlloc)/(1024*1024), runtime.NumGoroutine())
			previous = current
		}
	}
}
func (n *node) fastStatsSnapshot() fastStatsSnapshot {
	return fastStatsSnapshot{
		receivedPackets: n.stats.receivedPackets.Load(), receivedBytes: n.stats.receivedBytes.Load(),
		queueDrops: n.stats.queueDrops.Load(), sentPackets: n.stats.sentPackets.Load(), sentBytes: n.stats.sentBytes.Load(),
		rxQueueDrops: n.stats.rxQueueDrops.Load(), txQueueDrops: n.stats.txQueueDrops.Load(),
		deliveredPackets: n.stats.deliveredPackets.Load(), deliveredBytes: n.stats.deliveredBytes.Load(), deliveryDrops: n.stats.deliveryDrops.Load(),
		controlRxPackets: n.stats.controlRxPackets.Load(), controlRxBytes: n.stats.controlRxBytes.Load(), controlTxPackets: n.stats.controlTxPackets.Load(), controlTxBytes: n.stats.controlTxBytes.Load(),
	}
}
func (n *node) enqueueFast(data []byte, addr *net.UDPAddr) {
	n.stats.receivedPackets.Add(1)
	n.stats.receivedBytes.Add(uint64(len(data) + 28))
	if len(data) > maxFastFrame {
		n.debugf("drop fast frame from %s: exceeds MTU (%d bytes)", addr, len(data))
		return
	}
	// ReadBatch reuses its buffers after this call. Copy only fast packets into
	// a bounded pool so workers can decrypt in parallel without retaining the
	// 60 KiB control-plane receive buffers.
	owned := n.fastPool.Get().([]byte)[:len(data)]
	copy(owned, data)
	select {
	case n.fastQueue <- fastFrame{data: owned, addr: addr}:
	default:
		// UDP has no backpressure. A bounded queue makes overload a visible
		// packet drop instead of an unbounded allocation or stalled receiver.
		n.fastPool.Put(owned[:maxFastFrame])
		n.stats.queueDrops.Add(1)
		n.stats.rxQueueDrops.Add(1)
		n.debugf("drop fast frame from %s: worker queue full", addr)
	}
}
func (n *node) receive(ctx context.Context) {
	n.receiveMu.Lock()
	n.receiveCtx = ctx
	n.receiveStarted = true
	conns := n.transportConns()
	for _, conn := range conns {
		if _, exists := n.receiveSockets[conn]; exists {
			continue
		}
		n.receiveSockets[conn] = struct{}{}
		n.receiveWG.Add(1)
		go n.receiveSocket(ctx, conn)
	}
	n.receiveMu.Unlock()
	<-ctx.Done()
	n.receiveWG.Wait()
	close(n.fastQueue)
}
func (n *node) data(p protocol.Packet) {
	if rawIP, ok := p.Payload["ip"].(map[string]any); ok {
		sealed := make(map[string]string, len(rawIP))
		for key, value := range rawIP {
			if text, ok := value.(string); ok {
				sealed[key] = text
			}
		}
		n.handleLegacyIPFragment(p.Source, sealed)
		return
	}
	k, _, e := n.peerKey(p.Source)
	if e != nil {
		return
	}
	x, ok := p.Payload["sealed"].(map[string]any)
	if !ok {
		return
	}
	s := map[string]string{}
	for k, v := range x {
		if z, ok := v.(string); ok {
			s[k] = z
		}
	}
	raw, e := protocol.Open(k, s, []byte(p.Source+":"+n.id.ID))
	if e != nil {
		return
	}
	var m struct {
		Type string         `json:"type"`
		Body map[string]any `json:"body"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	switch m.Type {
	case "SERVICE_REQUEST":
		n.serviceRequest(p.Source, p.ID, m.Body)
	case "SERVICE_RESPONSE":
		rid, _ := m.Body["request_id"].(string)
		n.mu.RLock()
		ch := n.pending[rid]
		n.mu.RUnlock()
		if ch != nil {
			r := serviceResult{}
			r.Data, _ = m.Body["data"].(string)
			r.Error, _ = m.Body["error"].(string)
			select {
			case ch <- r:
			default:
			}
		}
	case "TUNNEL_OPEN":
		n.tunnelOpen(p.Source, m.Body)
	case "TUNNEL_DATA":
		n.tunnelData(p.Source, m.Body)
	case "TUNNEL_CLOSE":
		n.tunnelClose(p.Source, m.Body)
	case "IP_PACKET":
		encoded, _ := m.Body["data"].(string)
		if payload, err := protocol.B64Decode(encoded); err == nil {
			n.deliver(p.Source, payload)
		}
	}
}
func (n *node) serviceRequest(src, rid string, b map[string]any) {
	name, _ := b["service"].(string)
	if _, ok := n.services[name]; !ok || (!n.allow["*"] && !n.allow[src]) {
		n.encrypted(src, "SERVICE_RESPONSE", map[string]any{"request_id": rid, "error": "service unavailable"}, "")
		return
	}
	encoded, _ := b["data"].(string)
	raw, e := protocol.B64Decode(encoded)
	if e != nil || len(raw) > maxRequest {
		n.encrypted(src, "SERVICE_RESPONSE", map[string]any{"request_id": rid, "error": "invalid request"}, "")
		return
	}
	c, e := net.DialTimeout("tcp", n.services[name], 5*time.Second)
	if e == nil {
		c.SetDeadline(time.Now().Add(7 * time.Second))
		_, e = c.Write(raw)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(c, maxResponse+1))
			if len(raw) > maxResponse {
				e = errors.New("response too large")
			}
		}
		c.Close()
	}
	out := map[string]any{"request_id": rid}
	if e != nil {
		out["error"] = e.Error()
	} else {
		out["data"] = protocol.B64Encode(raw)
	}
	n.encrypted(src, "SERVICE_RESPONSE", out, "")
}
func (n *node) call(dst, name string, data []byte) ([]byte, error) {
	dst, e := n.resolve(dst)
	if e != nil {
		return nil, e
	}
	p := protocol.NewPacket("", "", "", nil)
	id := p.ID
	ch := make(chan serviceResult, 1)
	n.mu.Lock()
	n.pending[id] = ch
	n.mu.Unlock()
	defer func() { n.mu.Lock(); delete(n.pending, id); n.mu.Unlock() }()
	if !n.encrypted(dst, "SERVICE_REQUEST", map[string]any{"service": name, "data": protocol.B64Encode(data)}, id) {
		return nil, errors.New("could not send service request")
	}
	serviceTimer := time.NewTimer(30 * time.Second)
	defer serviceTimer.Stop()
	select {
	case x := <-ch:
		if x.Error != "" {
			return nil, errors.New(x.Error)
		}
		return protocol.B64Decode(x.Data)
	case <-serviceTimer.C:
		return nil, errors.New("service response timed out")
	}
}
func (n *node) close() {
	n.closing.Store(true)
	if n.stop != nil {
		n.stop()
	}
	conn := n.currentUDPConn()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	n.symmetricConnMu.Lock()
	for _, extra := range n.symmetricConns {
		if extra != nil && extra != conn {
			_ = extra.Close()
		}
	}
	n.symmetricConns = map[string]*net.UDPConn{}
	n.symmetricConnMu.Unlock()
	if n.tun != nil {
		cleanupTUN(n.c.tun, n.installedRoutes, n.tunLUID)
	}
	cleanupPlatformNetwork(port)
	if n.tun != nil {
		n.tun.Close()
	}
	if n.lanConn != nil {
		_ = n.lanConn.Close()
	}
	n.controlMu.Lock()
	if n.control != nil {
		_ = n.control.Close()
		n.control = nil
	}
	n.controlMu.Unlock()
}
func (n *node) handleDatagram(datagram []byte, address *net.UDPAddr) {
	if len(datagram) >= len(fastMagicBytes) && bytes.Equal(datagram[:len(fastMagicBytes)], fastMagicBytes) {
		n.enqueueFast(datagram, address)
		return
	}
	n.stats.controlRxPackets.Add(1)
	n.stats.controlRxBytes.Add(uint64(len(datagram) + 28)) // IPv4 + UDP overhead.
	var p protocol.Packet
	var e error
	if protocol.IsCompact(datagram) {
		p, e = protocol.DecodeCompact(datagram, n.key)
	} else {
		p, e = protocol.DecodePacket(datagram, n.key)
	}
	if e != nil || !n.remember(p.ID) {
		return
	}
	compact := protocol.IsCompact(datagram)
	if compact {
		switch p.Type {
		case "PING", "PONG", "HELLO", "HELLO_ACK":
			// The peer just proved it speaks the binary format, so compact
			// HELLO/HELLO_ACK toward it is safe. Unknown senders are marked as
			// soon as they appear in the neighbor table; the next compact PING
			// (15 s away) covers the gap.
			n.markCompactHello(p.Source)
		}
	}
	if p.Destination == n.id.ID && confirmsDirectPath(p.Type, p.TTL) {
		n.touch(p.Source, address)
	}
	if p.Destination != n.id.ID {
		if n.c.role == "superpeer" {
			if q, e := p.DecTTL(); e == nil {
				n.send(q)
			}
		}
		return
	}
	switch p.Type {
	case "HELLO":
		n.ensureNeighbor(p.Source)
		n.send(protocol.NewPacket("HELLO_ACK", n.id.ID, p.Source, map[string]any{"session_id": payloadString(p, "session_id")}))
	case "HELLO_ACK":
		n.debugf("received HELLO_ACK from %s; completing symmetric scan", p.Source[:8])
		n.completeSymmetricScan(p.Source, payloadString(p, "session_id"))
	case "PING":
		pong := protocol.NewPacket("PONG", n.id.ID, p.Source, map[string]any{"ping_id": p.ID})
		if compact {
			// Reply in the format the PING used so mixed-version fleets stay
			// interoperable during rolling upgrades.
			n.sendCompact(pong, address)
		} else {
			n.sendToAddress(pong, address)
		}
	case "PONG":
		n.handlePong(p)
	case "SYMMETRIC_BURST":
		n.ensureNeighbor(p.Source)
		n.handleSymmetricBurst(p, address)
	case "DATA":
		n.ensureNeighbor(p.Source)
		n.data(p)
	}
}
