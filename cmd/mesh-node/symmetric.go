package main

import (
	"container/heap"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	_ "net/http/pprof"
	"runtime"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"
)

func (n *node) cancelObsoleteSymmetricScans() {
	n.mu.RLock()
	neighbors := make(map[string]bool, len(n.neighbors))
	for id := range n.neighbors {
		neighbors[id] = true
	}
	n.mu.RUnlock()
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()
	for id, cancel := range n.symmetricScans {
		if neighbors[id] {
			continue
		}
		delete(n.symmetricScans, id)
		close(cancel)
		delete(n.symmetricSessions, id)
		delete(n.symmetricConnected, id)
		delete(n.symmetricBurstAt, id)
		delete(n.symmetricBurstSess, id)
	}
}
func (p pq) Len() int           { return len(p) }
func (p pq) Less(i, j int) bool { return p[i].cost < p[j].cost }
func (p pq) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)        { *p = append(*p, x.(qitem)) }
func (p *pq) Pop() any          { x := (*p)[len(*p)-1]; *p = (*p)[:len(*p)-1]; return x }
func (n *node) computeRoutes() (routes, fallbacks map[string]string) {
	adjacency := map[string][]qitem{}
	for _, edge := range n.links {
		adjacency[edge.A] = append(adjacency[edge.A], qitem{edge.B, edge.Cost})
		adjacency[edge.B] = append(adjacency[edge.B], qitem{edge.A, edge.Cost})
	}
	previous := n.firstHopTable(adjacency, "")
	routes = map[string]string{}
	byPrimary := map[string][]string{}
	for d := range n.dir {
		if d == n.id.ID {
			continue
		}
		if p, ok := n.neighbors[d]; ok && n.usable(p) {
			// A usable direct neighbor always wins over relaying: the packet
			// leaves immediately instead of depending on intermediate nodes.
			routes[d] = d
			continue
		}
		if hop := firstHopFrom(previous, d, n.id.ID); hop != "" {
			routes[d] = hop
			byPrimary[hop] = append(byPrimary[hop], d)
		}
	}
	fallbacks = map[string]string{}
	for hop, dests := range byPrimary {
		// One extra Dijkstra per distinct first hop (at most this node's own
		// degree), not per destination.
		alt := n.firstHopTable(adjacency, hop)
		for _, d := range dests {
			if f := firstHopFrom(alt, d, n.id.ID); f != "" && f != hop {
				fallbacks[d] = f
			}
		}
	}
	return routes, fallbacks
}
func (n *node) firstHopTable(adjacency map[string][]qitem, exclude string) map[string]string {
	costs := map[string]float64{n.id.ID: 0}
	previous := map[string]string{}
	queue := &pq{{n.id.ID, 0}}
	heap.Init(queue)
	for queue.Len() > 0 {
		current := heap.Pop(queue).(qitem)
		if current.cost != costs[current.id] {
			continue
		}
		for _, candidate := range adjacency[current.id] {
			if current.id == n.id.ID {
				if candidate.id == exclude {
					continue
				}
				if !n.usable(n.neighbors[candidate.id]) {
					continue
				}
			}
			candidateCost := current.cost + candidate.cost
			if existing, ok := costs[candidate.id]; !ok || candidateCost < existing {
				costs[candidate.id] = candidateCost
				previous[candidate.id] = current.id
				heap.Push(queue, qitem{candidate.id, candidateCost})
			}
		}
	}
	return previous
}
func firstHopFrom(previous map[string]string, destination, self string) string {
	hop := destination
	for previous[hop] != "" && previous[hop] != self {
		hop = previous[hop]
	}
	if previous[hop] == self {
		return hop
	}
	return ""
}
func (n *node) start() error {
	if n.c.endpoint == "" {
		n.logf("detecting public UDP endpoint via STUN")
		endpoint, nat, e := n.detectEndpoint()
		if e != nil {
			return fmt.Errorf("detect external endpoint: %w", e)
		}
		n.c.endpoint = endpoint
		n.logf("public UDP endpoint detected: %s, NAT=%s", endpoint, nat)
		if n.c.nat == "auto" {
			n.c.nat = nat
		}
	}
	if n.c.nat == "auto" {
		n.c.nat = "cone"
	}
	if n.c.role == "superpeer" && n.c.nat != "cone" {
		return errors.New("superpeer requires cone NAT")
	}
	if e := n.register(); e != nil {
		return e
	}
	for name, addr := range n.services {
		host, port, _ := net.SplitHostPort(addr)
		pi, _ := net.LookupPort("tcp", port)
		if e := n.request("POST", "/v1/services", map[string]any{"node_id": n.id.ID, "name": name, "target_host": host, "target_port": pi, "allowed_nodes": strings.Join(n.c.allows, ",")}, &map[string]any{}); e != nil {
			return e
		}
	}
	if e := n.bootstrap(); e != nil {
		return e
	}
	if !n.establishSymmetricTransport() {
		return errors.New("symmetric NAT synchronization with a superpeer failed")
	}
	if n.c.tun != "" {
		f, e := openTUN(n.c.tun)
		if e != nil {
			return e
		}
		n.tun = f
		if d, ok := f.(interface{ setDebug(bool) }); ok {
			d.setDebug(n.c.debug)
		}
		if d, ok := f.(interface{ adapterLUID() uint64 }); ok {
			n.tunLUID = d.adapterLUID()
		}
		if n.c.autoTUN {
			if e := configureTUN(n.c.tun, n.c.meshIP, n.c.prefix, n.tunLUID); e != nil {
				_ = n.tun.Close()
				n.tun = nil
				return e
			}
			n.logf("TUN %s configured with %s/%d", n.c.tun, n.c.meshIP, n.c.prefix)
			if e := n.syncTUNRoutes(); e != nil {
				_ = n.tun.Close()
				n.tun = nil
				return e
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	if e := n.startPprof(); e != nil {
		return e
	}
	n.startUDPSender(ctx)
	n.startFastWorkers(ctx)
	n.startDeliverWorker(ctx)
	go n.receive(ctx)
	go n.monitorNetwork(ctx)
	go n.monitorControl(ctx)
	go n.periodic(ctx, helloInterval, n.helloAll)
	go n.periodic(ctx, pingInterval, n.pingAll)
	go n.periodic(ctx, heartbeat, func() {
		if e := n.register(); e != nil {
			n.logf("heartbeat failed: %v", e)
		}
	})
	go n.periodic(ctx, telemetryInterval, func() {
		if e := n.reportTelemetry(); e != nil {
			n.logf("telemetry failed: %v", e)
		}
	})
	go n.periodic(ctx, recoveryCheck, n.recoverNetwork)
	go n.periodic(ctx, endpointVerifyInterval, n.verifyEndpoint)
	go n.periodic(ctx, topologyPoll, func() {
		if err := n.bootstrap(); err != nil {
			n.logf("periodic topology refresh failed: %v", err)
		}
	})
	go n.linkHealth(ctx)
	if err := n.startLANDiscovery(ctx); err != nil {
		n.logf("LAN discovery unavailable: %v", err)
	}
	go n.serveDNS(ctx)
	if n.c.statsInterval > 0 {
		go n.statsLoop(ctx, n.c.statsInterval)
	}
	if n.tun != nil {
		go n.tunLoop(ctx)
	}
	port := n.currentUDPConn().LocalAddr().(*net.UDPAddr).Port
	if err := configurePlatformNetwork(port); err != nil {
		n.logf("automatic Windows firewall integration unavailable on UDP %d: %v", port, err)
	} else if runtime.GOOS == "windows" {
		n.logf("Windows firewall rule enabled for inbound UDP %d", port)
	}
	n.helloAll()
	// Establish direct paths immediately; waiting for the first keepalive
	// interval makes a freshly started node look offline unnecessarily long.
	n.pingAll()
	go func() {
		timer := time.NewTimer(initialTelemetryDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := n.reportTelemetry(); err != nil {
				n.logf("initial telemetry failed: %v", err)
			}
		}
	}()
	n.logf("listening on %s", n.currentUDPConn().LocalAddr())
	return nil
}
func (n *node) establishSymmetricTransport() bool {
	// Cone (and open) NATs use the normal UDP socket.  They must not enter the
	// symmetric scan below: it intentionally creates per-superpeer sockets.
	if n.c.nat != "symmetric" {
		return true
	}

	// A long symmetric-NAT scan can outlive the coordinator's node TTL.
	// Keep the registration lease alive before the normal periodic loops are
	// started (start() blocks here until transport selection completes).
	leaseStop := make(chan struct{})
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		ticker := time.NewTicker(heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := n.register(); err != nil {
					n.logf("symmetric scan lease refresh failed: %v", err)
				}
			case <-leaseStop:
				return
			}
		}
	}()
	defer func() { close(leaseStop); <-leaseDone }()
	// Bursts started before a network switch belong to the dead mapping;
	// a newer recovery pass re-establishes on the fresh network.
	generation := n.networkGen.Load()
	for attempt := 1; attempt <= symmetricBurstRetries; attempt++ {
		if n.networkGen.Load() != generation {
			return false
		}
		relays := n.symmetricRelays()
		ready := 0
		started := 0
		for _, relay := range relays {
			if n.symmetricTransportReady(relay.id) || n.relayLANLive(relay.id) {
				// A traffic-confirmed LAN path already serves the relay through
				// the regular socket. Probing its public endpoint from the same
				// LAN hairpins through the NAT (often unsupported) and each
				// attempt burns hundreds of source ports in the router's
				// conntrack table.
				ready++
				continue
			}
			if n.symmetricBackoffWait(relay.id) > 0 {
				continue
			}
			started++
			if n.establishSymmetricTransportOnce(relay.id, &relay.peer, attempt) {
				ready++
				n.logf("symmetric NAT connected to superpeer %s", relay.id[:8])
			}
		}
		if len(relays) > 0 && ready == len(relays) {
			return true
		}
		if started == 0 {
			// Every relay is ready-or-backing-off; further rounds cannot make
			// progress and would only spin.
			break
		}
		if attempt < symmetricBurstRetries {
			n.logf("symmetric burst retry round %d/%d", attempt, symmetricBurstRetries-1)
			if err := n.bootstrap(); err != nil {
				n.logf("topology refresh before symmetric retry failed: %v", err)
			}
			time.Sleep(symmetricRetryDelay)
		}
	}
	return n.symmetricTransportCount() > 0 || n.someRelayLANLive()
}
func (n *node) relayLANLive(relayID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return freshLAN(n.neighbors[relayID], time.Now())
}
func (n *node) someRelayLANLive() bool {
	now := time.Now()
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, candidate := range n.neighbors {
		if candidate.Role == "superpeer" && freshLAN(candidate, now) {
			return true
		}
	}
	return false
}
func (n *node) establishSymmetricTransportOnce(relayID string, relay *peer, attempt int) (ok bool) {
	if n.c.nat != "symmetric" {
		return true
	}
	if n.symmetricTransportReady(relayID) {
		return true
	}
	if n.relayLANLive(relayID) {
		n.logf("symmetric NAT: superpeer %s is reachable via LAN; skipping probe burst", relayID[:8])
		return true
	}
	// Exponential per-relay backoff after failed bursts. Every 5-second
	// linkHealth tick used to restart the full rendezvous + 500-socket scan,
	// flooding conntrack and the coordinator without improving the odds.
	if wait := n.symmetricBackoffWait(relayID); wait > 0 {
		n.debugf("symmetric scan for %s postponed %s by previous failures", relayID[:8], wait.Round(time.Second))
		return false
	}
	// Share one burst per relay. Startup, roaming recovery and per-edge
	// retries used to run independent scans; concurrent rendezvous requests
	// also cancelled each other on the relay side (startSymmetricScan keeps
	// only the newest session), so neither scan could ever succeed.
	n.symmetricBurstMu.Lock()
	if call := n.symmetricBurstInFlight[relayID]; call != nil {
		n.symmetricBurstMu.Unlock()
		n.debugf("symmetric scan for %s already in flight; joining", relayID[:8])
		select {
		case <-call.done:
		case <-time.After(symmetricBurstTimeout + 15*time.Second):
		}
		return call.ok
	}
	call := &symmetricBurstCall{done: make(chan struct{})}
	n.symmetricBurstInFlight[relayID] = call
	n.symmetricBurstMu.Unlock()
	defer func() {
		n.symmetricBurstMu.Lock()
		if n.symmetricBurstInFlight[relayID] == call {
			delete(n.symmetricBurstInFlight, relayID)
		}
		n.symmetricBurstMu.Unlock()
		call.ok = ok
		close(call.done)
	}()
	// A burst that started before a network switch must not install its
	// socket afterwards: it is pinned to the dead network's mapping.
	generation := n.networkGen.Load()
	endpoint, err := net.ResolveUDPAddr("udp", relay.Endpoint)
	if err != nil {
		n.logf("invalid superpeer endpoint: %v", err)
		return false
	}
	sessionID, err := newSymmetricSessionID()
	if err != nil {
		n.logf("create symmetric rendezvous session: %v", err)
		return false
	}
	proceed, coordinated := n.requestSymmetricScan(relayID, sessionID)
	if !proceed {
		n.symmetricBurstFailed(relayID)
		return false
	}
	if !coordinated {
		// Old peers do not echo a session identifier in HELLO. Keep the
		// complete legacy wire format when the coordinator reports no API.
		sessionID = ""
	}

	responses := make(chan symmetricReply, symmetricBurstSize)
	sockets := make([]*net.UDPConn, 0, symmetricBurstSize)
	iface := resolveBindIface(n.c.bindIface)
	n.logf("symmetric NAT: probing %d UDP ports via %s (attempt %d/%d)", symmetricBurstSize, relayID[:8], attempt, symmetricBurstRetries)
	for range symmetricBurstSize {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(n.c.bind)})
		if err != nil {
			continue
		}
		if iface != "" {
			// Probe sockets must ride the same uplink as the transport: on a
			// phone with a VPN TUN (VLESS/Happ), wildcard probes vanish into
			// the proxy and the reverse scan can never find them.
			if err := bindUDPInterface(probe, iface); err != nil {
				probe.Close()
				continue
			}
		}
		burst := protocol.NewPacket("SYMMETRIC_BURST", n.id.ID, relayID, map[string]any{"session_id": sessionID})
		encoded, err := protocol.EncodePacket(burst, n.key)
		if err != nil {
			probe.Close()
			continue
		}
		if _, err = probe.WriteToUDP(encoded, endpoint); err != nil {
			probe.Close()
			continue
		}
		configureUDPSocket(probe)
		sockets = append(sockets, probe)
		go n.awaitSymmetricHello(probe, relayID, sessionID, responses)
		// Pace the burst: dumping hundreds of packets back-to-back trips
		// uplink QoS and carrier-NAT rate limits on mobile networks.
		time.Sleep(scanDelay)
	}

	deadline := time.NewTimer(symmetricBurstTimeout)
	defer deadline.Stop()
	var selected *net.UDPConn
	for selected == nil {
		select {
		case received := <-responses:
			if n.networkGen.Load() != generation {
				// The network changed mid-burst: this socket belongs to the
				// previous mapping and must not become the transport.
				for _, probe := range sockets {
					_ = probe.Close()
				}
				n.debugf("symmetric scan for %s abandoned after network change", relayID[:8])
				return false
			}
			selected = received.conn
			// awaitSymmetricHello reads the handshake directly from the probe
			// socket, so it does not pass through handleDatagram/touch. Mark the
			// relay live here; otherwise linkHealth immediately sees a zero
			// lastRX after a successful scan and starts the same scan again.
			n.touch(relayID, received.addr)
			ack := protocol.NewPacket("HELLO_ACK", n.id.ID, relayID, map[string]any{"session_id": sessionID})
			if encoded, err := protocol.EncodePacket(ack, n.key); err == nil {
				_, _ = selected.WriteToUDP(encoded, received.addr)
			}
		case <-deadline.C:
			for _, probe := range sockets {
				_ = probe.Close()
			}
			n.logf("symmetric NAT burst timed out without HELLO")
			n.symmetricBurstFailed(relayID)
			return false
		}
	}
	for _, probe := range sockets {
		if probe != selected {
			_ = probe.Close()
		}
	}
	primary := n.installSymmetricConn(relayID, selected)
	if primary {
		previousEndpoint := n.c.endpoint
		if endpoint, _, err := n.detectEndpoint(); err == nil {
			n.c.endpoint = endpoint
			if endpointIPChanged(previousEndpoint, endpoint) {
				if err := n.register(); err != nil {
					n.logf("symmetric NAT endpoint update failed: %v", err)
				} else if err := n.bootstrap(); err != nil {
					n.logf("topology refresh after symmetric NAT update failed: %v", err)
				}
			}
		}
	}
	n.symmetricBurstSucceeded(relayID)
	n.logf("symmetric NAT synchronized through %s on %s", relayID[:8], selected.LocalAddr())
	return true
}
func newSymmetricSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (n *node) symmetricBackoffWait(relayID string) time.Duration {
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()
	due, ok := n.symmetricBackoff[relayID]
	if !ok {
		return 0
	}
	if wait := time.Until(due); wait > 0 {
		return wait
	}
	return 0
}
func (n *node) symmetricBurstFailed(relayID string) {
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()
	if n.symmetricFailures == nil {
		n.symmetricFailures = map[string]int{}
	}
	if n.symmetricBackoff == nil {
		n.symmetricBackoff = map[string]time.Time{}
	}
	n.symmetricFailures[relayID]++
	delay := symmetricRetryDelay
	for i := 1; i < n.symmetricFailures[relayID] && delay < symmetricBurstBackoffMax; i++ {
		delay *= 2
	}
	if delay > symmetricBurstBackoffMax {
		delay = symmetricBurstBackoffMax
	}
	n.symmetricBackoff[relayID] = time.Now().Add(delay)
}
func (n *node) symmetricBurstSucceeded(relayID string) {
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()
	delete(n.symmetricFailures, relayID)
	delete(n.symmetricBackoff, relayID)
}
