package main

import (
	"errors"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"time"

	"home-udp-mesh/internal/protocol"
)

func (n *node) speaksCompactHello(id string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	peer := n.neighbors[id]
	return peer != nil && time.Now().Before(peer.compactHelloUntil)
}
func (n *node) sendCompact(packet protocol.Packet, address *net.UDPAddr) {
	encoded, err := n.encodeCompact(packet)
	if err != nil {
		n.sendToAddress(packet, address)
		return
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return
	}
	_, _ = conn.WriteToUDP(encoded, address)
}
func (n *node) periodic(ctx context.Context, d time.Duration, f func()) {
	// Nodes commonly start at the same time (service restart, container
	// rollout, or a laptop waking up). A small per-loop phase prevents all
	// registrations, telemetry and topology refreshes from becoming one
	// control-plane burst. Keep short health loops immediate; they are useful
	// for fast recovery and do not generate meaningful traffic by themselves.
	if d >= 10*time.Second {
		phase := d / 5
		if phase > 5*time.Second {
			phase = 5 * time.Second
		}
		var seed [2]byte
		if _, err := rand.Read(seed[:]); err == nil {
			phase = time.Duration(binary.BigEndian.Uint16(seed[:])) % (phase + 1)
		}
		if phase > 0 {
			timer := time.NewTimer(phase)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}
func (n *node) startLANDiscovery(ctx context.Context) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: lanDiscoveryPort})
	if err != nil {
		return err
	}
	n.lanConn = conn
	go n.lanDiscoveryLoop(ctx, conn)
	n.broadcastLANDiscovery()
	go n.lanDiscoveryBurst(ctx)
	go n.periodic(ctx, lanDiscoveryInterval, n.broadcastLANDiscovery)
	go n.periodic(ctx, lanProbeInterval, n.probeLanCandidates)
	return nil
}
func (n *node) lanDiscoveryBurst(ctx context.Context) {
	delay := time.Second
	for i := 0; i < lanDiscoveryBurstCount; i++ {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.broadcastLANDiscovery()
		delay *= 2
	}
}
func (n *node) probeLanCandidates() {
	if !n.hasLAN() {
		// No physical LAN right now (mobile data): candidates cannot be
		// on-link, probing would just leak packets into the carrier network.
		return
	}
	type probe struct {
		id   string
		addr *net.UDPAddr
	}
	now := time.Now()
	n.mu.Lock()
	probes := make([]probe, 0, 4)
	for id, p := range n.neighbors {
		if len(p.LANAddrs) == 0 || now.Sub(p.lastLANProbe) < lanProbeInterval || freshLAN(p, now) {
			continue
		}
		p.lastLANProbe = now
		for _, raw := range p.LANAddrs {
			if len(probes) >= lanProbeMaxAddrs {
				break
			}
			addr, err := net.ResolveUDPAddr("udp4", raw)
			if err != nil || addr.IP == nil || !n.lanCandidateUsable(addr.IP) {
				continue
			}
			// A LAN candidate that equals a published NAT endpoint (this
			// node's own hole, or the candidate peer's) is not on-link:
			// unicating HELLO toward a hole punch walks the provider
			// mapping (ping and shared-bandwidth cost every probe round) and
			// whatever comes back confirms the NAT itself, not a LAN path.
			// lanCandidateUsable above only checks that the address looks
			// like LAN, so holes punched inside a private range still pass
			// through it and must be rejected here.
			if lanCandidateBlockedIP(addr.IP, n.c.endpoint, p.Endpoint) {
				continue
			}
			p.lastLAN = copyUDPAddr(addr)
			probes = append(probes, probe{id: id, addr: copyUDPAddr(addr)})
		}
	}
	n.mu.Unlock()
	for _, pr := range probes {
		n.debugf("LAN probe to %s at %s", pr.id[:8], pr.addr)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, pr.id, map[string]any{"public_key": n.id.Public}), pr.addr)
	}
}
func (n *node) broadcastLANDiscovery() {
	n.mu.RLock()
	if n.lanConn == nil {
		n.mu.RUnlock()
		return
	}
	conn := n.lanConn
	n.mu.RUnlock()
	if !n.meshHasOtherNodes() {
		// A lone node has nobody to discover: the broadcast would be noise.
		n.debugf("LAN discovery skipped: no other node in the mesh")
		return
	}
	port := n.currentUDPConn().LocalAddr().(*net.UDPAddr).Port
	p := protocol.NewPacket("LAN_DISCOVERY", n.id.ID, "", map[string]any{"udp_port": port})
	b, err := protocol.EncodePacket(p, n.key)
	if err != nil {
		return
	}
	// The limited broadcast alone finds peers unreliably: multi-homed hosts
	// send it out of the default-route interface only, and some Wi-Fi
	// drivers or APs drop it entirely. Every local subnet therefore also
	// receives a directed broadcast (192.168.1.255 style), which the routing
	// table delivers through the interface that actually owns the subnet.
	targets := append([]net.IP{net.IPv4bcast}, n.subnetBroadcastAddrs()...)
	for _, ip := range targets {
		if _, err = conn.WriteToUDP(b, &net.UDPAddr{IP: ip, Port: lanDiscoveryPort}); err != nil {
			n.debugf("LAN discovery broadcast to %s failed: %v", ip, err)
		}
	}
}
func (n *node) subnetBroadcastAddrs() []net.IP {
	subnets := n.localSubnets()
	out := make([]net.IP, 0, len(subnets))
	seen := map[uint32]bool{}
	for _, subnet := range subnets {
		ip, ok := broadcastForPrefix(subnet)
		if !ok {
			continue
		}
		key := binary.BigEndian.Uint32(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out
}
func broadcastForPrefix(subnet netip.Prefix) (net.IP, bool) {
	if !subnet.Addr().Is4() || subnet.Bits() <= 0 || subnet.Bits() >= 31 {
		return nil, false
	}
	raw := subnet.Masked().Addr().As4()
	addr := binary.BigEndian.Uint32(raw[:])
	addr |= 0xffffffff >> subnet.Bits()
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).To4(), true
}
func (n *node) lanDiscoveryLoop(ctx context.Context, conn *net.UDPConn) {
	buffer := make([]byte, protocol.MaxDatagramSize)
	for {
		length, address, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			n.debugf("LAN discovery receive failed: %v", err)
			continue
		}
		packet, err := protocol.DecodePacket(buffer[:length], n.key)
		if err != nil || packet.Type != "LAN_DISCOVERY" || packet.Source == n.id.ID {
			continue
		}
		var payload struct {
			Port int `json:"udp_port"`
		}
		raw, err := json.Marshal(packet.Payload)
		if err != nil || json.Unmarshal(raw, &payload) != nil || payload.Port < 1 || payload.Port > 65535 {
			continue
		}
		candidate := copyUDPAddr(&net.UDPAddr{IP: address.IP, Port: payload.Port})
		n.mu.Lock()
		peer := n.neighbors[packet.Source]
		if peer != nil && lanCandidateBlockedIP(address.IP, n.c.endpoint, peer.Endpoint) {
			// LAN-discovery traffic that arrived at a published NAT endpoint
			// walked a hole punch (provider NAT): the candidate is the NAT
			// itself, so it must not be adopted as a LAN route and probing it
			// would walk the provider mapping every round.
			} else if peer != nil {
			// Candidate only: lastLANRX is set by touch() once traffic actually
			// arrives from this address, so an unreachable candidate (LAN
			// segmentation, AP isolation) never suppresses the public path.
			peer.lastLAN = candidate
			peer.last = candidate
		} else {
			// The peer is not installed yet (still bootstrapping, or this node
			// just started). Buffer the candidate so it survives until
			// applyTopology creates the peer; dropping it used to leave the
			// NAT-hairpin public path as the only option.
			if n.pendingLAN == nil {
				n.pendingLAN = map[string]*net.UDPAddr{}
			}
			n.pendingLAN[packet.Source] = candidate
		}
		n.mu.Unlock()
		n.debugf("LAN endpoint candidate for %s: %s", packet.Source[:8], candidate)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, packet.Source, map[string]any{"public_key": n.id.Public}), candidate)
	}
}
func (n *node) resetTransportState() {
	n.mu.Lock()
	for _, peer := range n.neighbors {
		peer.last = nil
		peer.lastRX = time.Time{}
		peer.lastLAN = nil
		peer.lastLANRX = time.Time{}
		peer.lastPathLAN = false
		peer.lastLANProbe = time.Time{}
		peer.up = false
	}
	n.pendingLAN = map[string]*net.UDPAddr{}
	n.mu.Unlock()
	current := n.currentUDPConn()
	n.symmetricConnMu.Lock()
	for id, conn := range n.symmetricConns {
		if conn != nil && conn != current {
			_ = conn.Close()
		}
		delete(n.symmetricConns, id)
	}
	n.symmetricConns = map[string]*net.UDPConn{}
	n.symmetricConnMu.Unlock()
	n.symmetricMu.Lock()
	n.symmetricReady = false
	for id, cancel := range n.symmetricScans {
		delete(n.symmetricScans, id)
		close(cancel)
	}
	n.symmetricSessions = map[string]string{}
	n.symmetricAckWaiters = map[string]chan struct{}{}
	n.symmetricConnected = map[string]bool{}
	n.symmetricBurstAt = map[string]time.Time{}
	n.symmetricBurstSess = map[string]string{}
	// A new network means a new NAT mapping: scan failures observed on the
	// previous network say nothing about the fresh one, so clear the backoff.
	n.symmetricFailures = map[string]int{}
	n.symmetricBackoff = map[string]time.Time{}
	n.symmetricMu.Unlock()
}
func (n *node) restoreTUNNetwork() error {
	if n.tun == nil || !n.c.autoTUN {
		return nil
	}
	if err := configureTUN(n.c.tun, n.c.meshIP, n.c.prefix, n.tunLUID); err != nil {
		return err
	}
	return n.forceTUNRouteSync()
}
func (n *node) forceTUNRouteSync() error {
	n.routeMu.Lock()
	n.installedRoutes = map[string]bool{}
	n.routeMu.Unlock()
	return n.syncTUNRoutes()
}
func (n *node) deferRecovery(err error, action string) {
	n.recoveryFails++
	backoff := recoveryMinBackoff
	for i := 1; i < n.recoveryFails && backoff < recoveryMaxBackoff; i++ {
		backoff *= 2
	}
	if backoff > recoveryMaxBackoff {
		backoff = recoveryMaxBackoff
	}
	n.recoveryNext = time.Now().Add(backoff)
	n.logf("%s: %v; retrying in %s", action, err, backoff)
}
func (n *node) recoverNetwork() {
	n.mu.RLock()
	stale := len(n.neighbors) > 0
	for _, peer := range n.neighbors {
		// A single offline neighbor is normal in a mesh. Recovery of the
		// local NAT mapping is only justified when every observed neighbor is
		// stale; otherwise an unrelated peer can repeatedly disrupt healthy
		// traffic on this node.
		if (!peer.lastRX.IsZero() && time.Since(peer.lastRX) < linkTimeout) ||
			(peer.lastRX.IsZero() && time.Since(peer.discovered) < linkGrace) {
			stale = false
			break
		}
	}
	n.mu.RUnlock()
	if !stale || !n.recoveryMu.TryLock() {
		return
	}
	defer n.recoveryMu.Unlock()
	if time.Now().Before(n.recoveryNext) {
		return
	}
	n.logf("network link stale; refreshing STUN endpoint and topology")
	if err := n.rebindUDPConn(); err != nil {
		n.deferRecovery(err, "UDP socket recovery failed")
		return
	}
	n.resetTransportState()
	if err := n.restoreTUNNetwork(); err != nil {
		n.deferRecovery(err, "TUN network restore failed")
		return
	}
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		n.deferRecovery(err, "STUN recovery failed")
		return
	}
	previousEndpoint := n.c.endpoint
	ipChanged := endpointIPChanged(previousEndpoint, endpoint)
	n.c.endpoint = endpoint
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	if ipChanged {
		if err := n.register(); err != nil {
			n.deferRecovery(err, "re-register after network loss failed")
			return
		}
		if err := n.bootstrap(); err != nil {
			n.deferRecovery(err, "topology refresh after network loss failed")
			return
		}
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.deferRecovery(errors.New("symmetric handshake did not complete"), "symmetric transport recovery failed")
		return
	}
	n.recoveryFails = 0
	n.recoveryNext = time.Time{}
	n.helloAll()
	n.pingAll()
}
func (n *node) roamRefresh(attempt int) {
	if !n.recoveryMu.TryLock() {
		// recoverNetwork or a newer roam pass is in flight; that pass already
		// observes the new network.
		return
	}
	defer n.recoveryMu.Unlock()
	retry := func(stage string, err error) {
		n.logf("network change: %s: %v", stage, err)
		if attempt < endpointRefreshRetries {
			time.AfterFunc(endpointRefreshRetryDelay, func() { n.roamRefresh(attempt + 1) })
			return
		}
		n.logf("network change: giving up for now; keepalive recovery stays armed")
	}
	if err := n.rebindUDPConn(); err != nil {
		retry("UDP rebind failed", err)
		return
	}
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		// DNS and STUN are often unusable for the first seconds after a radio
		// transition; the retries below ride them out.
		retry("STUN check failed", err)
		return
	}
	if endpoint != n.c.endpoint {
		n.logf("network change: UDP endpoint changed %s -> %s", n.c.endpoint, endpoint)
		n.c.endpoint = endpoint
	}
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	// Every peer.last entry and every per-superpeer socket belongs to the old
	// NAT mapping. Drop them before rebuilding; keeping them made a Wi-Fi ->
	// LTE transition keep stale symmetric state and never start a new scan.
	n.resetTransportState()
	if err := n.restoreTUNNetwork(); err != nil {
		n.logf("network change: TUN network restore failed: %v", err)
	}
	// The heartbeat also publishes the fresh endpoint to the coordinator.
	if err := n.register(); err != nil {
		retry("re-register failed", err)
		return
	}
	if err := n.bootstrap(); err != nil {
		retry("topology refresh failed", err)
		return
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.logf("network change: symmetric handshake did not complete; link health will retry")
	}
	n.helloAll()
	n.pingAll()
}
