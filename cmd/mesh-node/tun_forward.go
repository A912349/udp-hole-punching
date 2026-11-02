package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	_ "net/http/pprof"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"
)

func (n *node) transportConns() []*net.UDPConn {
	seen := map[*net.UDPConn]struct{}{}
	conns := make([]*net.UDPConn, 0, 1+n.symmetricTransportCount())
	if conn := n.currentUDPConn(); conn != nil {
		seen[conn] = struct{}{}
		conns = append(conns, conn)
	}
	n.symmetricConnMu.RLock()
	for _, conn := range n.symmetricConns {
		if conn != nil {
			if _, exists := seen[conn]; !exists {
				seen[conn] = struct{}{}
				conns = append(conns, conn)
			}
		}
	}
	n.symmetricConnMu.RUnlock()
	return conns
}
func (n *node) addReceiveSocket(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	n.receiveMu.Lock()
	defer n.receiveMu.Unlock()
	if !n.receiveStarted || n.receiveCtx == nil {
		return
	}
	if _, exists := n.receiveSockets[conn]; exists {
		return
	}
	if n.receiveCtx.Err() != nil {
		return
	}
	n.receiveSockets[conn] = struct{}{}
	n.receiveWG.Add(1)
	go n.receiveSocket(n.receiveCtx, conn)
}
func (n *node) receiveSocket(ctx context.Context, conn *net.UDPConn) {
	defer n.receiveWG.Done()
	defer func() {
		n.receiveMu.Lock()
		delete(n.receiveSockets, conn)
		n.receiveMu.Unlock()
	}()
	reader := newUDPBatchReader(conn)
	for {
		n.udpReadMu.RLock()
		// Every read must stay inside a bounded window. rebindUDPConn and STUN
		// wait for the exclusive lock, and a reader parked forever in recvmsg on
		// a socket that stopped receiving traffic (dead NAT mapping after an IP
		// change) would block them permanently, so the endpoint refresh after a
		// network change never completed and the node stayed on a dead endpoint.
		_ = conn.SetReadDeadline(time.Now().Add(udpReadWindow))
		datagrams, e := reader.read()
		n.udpReadMu.RUnlock()
		if e != nil {
			// A socket replacement deliberately closes the old connection while
			// the node context stays alive. ReadFromUDP then returns net.ErrClosed
			// immediately forever; retrying it here used to leave one hot goroutine
			// behind after every network recovery.
			if ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				return
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			n.debugf("UDP receive failed: %v", e)
			// Protect against platform-specific persistent socket errors as well.
			// UDP has no useful work to do until the socket recovers or is replaced.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		for _, datagram := range datagrams {
			n.handleDatagram(datagram.data, datagram.address)
		}
	}
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
func (n *node) writeControlUDP(conn *net.UDPConn, data []byte, address *net.UDPAddr) (int, error) {
	written, err := conn.WriteToUDP(data, address)
	if err == nil {
		n.stats.controlTxPackets.Add(1)
		n.stats.controlTxBytes.Add(uint64(written + 28))
	}
	return written, err
}
func (n *node) handlePong(packet protocol.Packet) {
	id, ok := packet.Payload["ping_id"].(string)
	if !ok || packet.TTL != protocol.DefaultTTL {
		return
	}
	n.pingMu.Lock()
	probe, exists := n.pings[id]
	if exists && probe.peerID == packet.Source {
		delete(n.pings, id)
	}
	n.pingMu.Unlock()
	if !exists || probe.peerID != packet.Source || probe.sent.IsZero() {
		return
	}
	n.mu.Lock()
	if peer := n.neighbors[packet.Source]; peer != nil {
		sample := float64(time.Since(probe.sent).Microseconds()) / 1000
		// A single stalled probe must not double the reported RTT, so the
		// sample lands in an EWMA instead of replacing the estimate. A probe
		// that was answered proves the link is currently alive: decay loss.
		if peer.rttMS == 0 || peer.rttMS > 60000 {
			peer.rttMS = sample
		} else {
			peer.rttMS = peer.rttMS*rttProbeSmooth + sample*(1-rttProbeSmooth)
		}
		peer.lossEMA *= lossProbeRecover
	}
	n.mu.Unlock()
}
func confirmsDirectPath(packetType string, ttl int) bool {
	if ttl != protocol.DefaultTTL {
		return false
	}
	switch packetType {
	case "HELLO", "HELLO_ACK", "PING", "PONG":
		return true
	default:
		return false
	}
}
func (n *node) remember(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seen[id]; ok {
		return false
	}
	n.seen[id] = struct{}{}
	if len(n.seen) > 10000 {
		for k := range n.seen {
			delete(n.seen, k)
			break
		}
	}
	return true
}
func (n *node) rememberFast(id [12]byte) bool {
	n.fastSeenMu.Lock()
	defer n.fastSeenMu.Unlock()
	if _, ok := n.fastSeen[id]; ok {
		return false
	}
	if len(n.fastSeenRing) < fastSeenCapacity {
		n.fastSeenRing = append(n.fastSeenRing, id)
	} else {
		delete(n.fastSeen, n.fastSeenRing[n.fastSeenNext])
		n.fastSeenRing[n.fastSeenNext] = id
		n.fastSeenNext++
		if n.fastSeenNext == fastSeenCapacity {
			n.fastSeenNext = 0
		}
	}
	n.fastSeen[id] = struct{}{}
	return true
}
func (n *node) nextPacketID(dst []byte) bool {
	if len(dst) != 12 {
		return false
	}
	for {
		previous := n.packetCounter.Load()
		if previous == ^uint64(0) {
			return false
		}
		count := previous + 1
		if n.packetCounter.CompareAndSwap(previous, count) {
			copy(dst, n.packetPrefix[:])
			binary.BigEndian.PutUint64(dst[len(n.packetPrefix):], count)
			return true
		}
	}
}
func (n *node) meshHasOtherNodes() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for id := range n.neighbors {
		if id != n.id.ID {
			return true
		}
	}
	for id := range n.dir {
		if id != n.id.ID {
			return true
		}
	}
	return false
}
func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}
func virtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "lo" || strings.HasPrefix(lower, "lo0") || strings.Contains(lower, "loopback") || strings.Contains(lower, "bluetooth") {
		return true
	}
	// Docker user-defined bridges are br-<12 hex chars>; OpenWrt's real LAN
	// bridge is br-lan / br-wan and must not be filtered.
	if strings.HasPrefix(lower, "br-") && len(lower) > 6 {
		return true
	}
	for _, prefix := range []string{"docker", "veth", "virbr", "vmnet", "vboxnet", "wsl", "tailscale", "zerotier", "zt", "tun", "tap", "utun", "wg", "ifb", "dummy"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, part := range []string{"virtual", "vmware", "hyper-v"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}
func (n *node) localSubnets() []netip.Prefix {
	n.subnetsMu.Lock()
	defer n.subnetsMu.Unlock()
	now := time.Now()
	if n.subnets != nil && now.Sub(n.subnetsAt) < localSubnetsRefresh {
		return n.subnets
	}
	n.subnets = n.collectSubnets(false)
	n.subnetsAt = now
	return n.subnets
}
func (n *node) lanSubnets() []netip.Prefix {
	n.subnetsMu.Lock()
	defer n.subnetsMu.Unlock()
	now := time.Now()
	if n.lanSubnetCache != nil && now.Sub(n.lanSubnetsAt) < localSubnetsRefresh {
		return n.lanSubnetCache
	}
	n.lanSubnetCache = n.collectSubnets(true)
	n.lanSubnetsAt = now
	return n.lanSubnetCache
}
func (n *node) hasLAN() bool {
	return len(n.lanSubnets()) > 0
}
func (n *node) collectSubnets(lanOnly bool) []netip.Prefix {
	subnets := make([]netip.Prefix, 0, 4)
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || virtualInterfaceName(iface.Name) || (n.c.tun != "" && iface.Name == n.c.tun) {
				continue
			}
			if lanOnly && wwanInterfaceName(iface.Name) {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipnet.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || n.isMeshAddr(ip) {
					continue
				}
				if lanOnly && !ip.IsPrivate() {
					continue
				}
				bits, _ := net.IPMask(ipnet.Mask).Size()
				subnets = append(subnets, netip.PrefixFrom(ip, bits))
			}
		}
	}
	return subnets
}
func (n *node) isMeshAddr(ip netip.Addr) bool {
	mesh := n.meshIPv4.Load()
	if mesh == 0 || n.c.prefix <= 0 || n.c.prefix > 32 {
		return false
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], mesh)
	meshAddr, ok := netip.AddrFromSlice(raw[:])
	if !ok {
		return false
	}
	return netip.PrefixFrom(meshAddr, n.c.prefix).Contains(ip)
}
func (n *node) advertisedLanAddrs() []string {
	conn := n.currentUDPConn()
	if conn == nil {
		// No socket (startup or a failed rebind): nothing to advertise.
		return nil
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(ip netip.Addr) {
		if len(out) >= lanAdvertiseMax || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	// Advertise only genuine LAN material: private addresses on non-modem
	// interfaces. Advertising carrier ranges (10.x inside CGNAT, exotic
	// public ranges) made other nodes probe addresses inside the provider's
	// network.
	for _, prefix := range n.lanSubnets() {
		if !prefix.Addr().IsPrivate() {
			continue
		}
		add(prefix.Addr())
	}
	return out
}
func (n *node) localSource(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
		return true
	}
	for _, subnet := range n.localSubnets() {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}
func wwanInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"rmnet", "ccmni", "pdp", "wwan"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
func (n *node) lanCandidateUsable(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if addr.IsPrivate() {
		return n.hasLAN()
	}
	for _, subnet := range n.localSubnets() {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}
func (n *node) sameNAT(p *peer) bool {
	if p == nil || p.Endpoint == "" || n.c.endpoint == "" {
		return false
	}
	peerIP := endpointIP(p.Endpoint)
	return peerIP != "" && peerIP == endpointIP(n.c.endpoint)
}
func freshLAN(p *peer, now time.Time) bool {
	return p != nil && p.lastLAN != nil && now.Sub(p.lastLANRX) < lanHoldTimeout
}
func (n *node) touch(id string, a net.Addr) {
	// Classify the source before taking the topology lock: the subnet cache
	// may refresh and touch the network stack.
	lanSource := false
	address, isUDP := a.(*net.UDPAddr)
	if isUDP {
		lanSource = n.localSource(address.IP)
	}
	now := time.Now()
	n.mu.Lock()
	if p := n.neighbors[id]; p != nil {
		if isUDP {
			if lanSource {
				// A LAN address always wins for sending: same-segment traffic
				// does not traverse the NAT device at all.
				p.lastLAN = copyUDPAddr(address)
				p.lastLANRX = now
				p.last = p.lastLAN
			} else if !freshLAN(p, now) || p.last != net.Addr(p.lastLAN) {
				// Public source: either a real WAN path or NAT hairpin. The
				// send target keeps a small hysteresis (below) so one hairpin
				// datagram does not flip where the next probes are sent.
				p.last = copyUDPAddr(address)
			}
		} else {
			p.last = a
		}
		// Classification is strictly per-packet: the source of the most
		// recent datagram decides LAN vs internet, with no holdover. NAT
		// rewrites the source to a public address on any path that leaves
		// the LAN, so a private source means the traffic stayed local.
		p.lastPathLAN = lanSource
		p.lastRX = now
		p.up = true
	}
	n.mu.Unlock()
}
func (n *node) ensureNeighbor(id string) {
	n.mu.RLock()
	known := n.neighbors[id] != nil
	n.mu.RUnlock()
	if known {
		return
	}
	// Unknown packets can arrive in bursts (or be sent by a stale/malicious
	// member). Coalesce them into one asynchronous refresh so the UDP receive
	// loop is never blocked and they cannot create a control-plane CPU storm.
	if !n.topologyRefreshMu.TryLock() {
		return
	}
	now := time.Now()
	if now.Before(n.topologyRefreshNext) {
		n.topologyRefreshMu.Unlock()
		return
	}
	n.topologyRefreshNext = now.Add(refresh)
	go func() {
		defer n.topologyRefreshMu.Unlock()
		n.logf("received traffic from new node %s; refreshing topology", id[:8])
		if err := n.bootstrap(); err != nil {
			n.logf("topology refresh failed: %v", err)
		}
	}()
}
func (n *node) linkHealth(ctx context.Context) {
	ticker := time.NewTicker(linkHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deadEdges := make([]peer, 0)
			stateChanged := false
			n.mu.Lock()
			for id, peer := range n.neighbors {
				live := n.usable(peer)
				if peer.up != live {
					stateChanged = true
					peer.up = live
					state := "down"
					if live {
						state = "up"
					}
					n.logf("link %s %s", id[:8], state)
				}
				if !live {
					deadEdges = append(deadEdges, *peer)
				}
			}
			n.mu.Unlock()
			if stateChanged {
				n.mu.Lock()
				n.routes, n.altRoutes = n.computeRoutes()
				n.mu.Unlock()
			}
			for _, peer := range deadEdges {
				// The up/down transition was already logged above. Retry
				// scheduling and its logging live inside retryDeadEdge: a line
				// here repeated every tick made mobile logs useless.
				n.debugf("edge %s is dead; retry scheduled", peer.ID[:8])
				n.retryDeadEdge(peer.ID, peer)
			}
		}
	}
}
