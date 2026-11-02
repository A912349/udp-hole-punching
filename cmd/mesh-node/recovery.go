package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	_ "net/http/pprof"
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
	encoded, err := protocol.EncodeCompact(packet, n.key)
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
		if peer != nil {
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
