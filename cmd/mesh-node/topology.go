package main

import (
	"encoding/binary"
	"fmt"
	"net"
	_ "net/http/pprof"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"
)

func (n *node) bootstrap() error {
	n.mu.RLock()
	version := n.topologyVersion
	n.mu.RUnlock()
	path := "/v1/bootstrap/" + n.id.ID
	// Older coordinators ignore this optional body and return a full snapshot.
	var condition any
	if version != "" {
		condition = map[string]string{"version": version}
	}
	var t topology
	if e := n.request("GET", path, condition, &t); e != nil {
		// The coordinator intentionally hides stale nodes from topology. A
		// short control-plane/NAT interruption can therefore make bootstrap
		// return 404 even though the node still exists. Refresh the lease and
		// retry once instead of terminating the client.
		if strings.Contains(e.Error(), "404: unknown node") {
			n.logf("bootstrap returned unknown node; refreshing registration lease")
			if registerErr := n.register(); registerErr != nil {
				// A revoked identity keeps failing forever; say so once, loudly,
				// instead of leaving an opaque retry loop in the logs.
				if strings.Contains(registerErr.Error(), "status 403") && !n.revokedLogged.Swap(true) {
					n.logf("coordinator banned this node identity; removal is permanent until unbanned in the admin panel — wipe local state or use a fresh setup key to re-enroll")
				}
				return fmt.Errorf("bootstrap unknown node; re-register failed: %w", registerErr)
			}
			if retryErr := n.request("GET", path, condition, &t); retryErr != nil {
				return retryErr
			}
		} else {
			return e
		}
	}
	n.applyTopology(t)
	return nil
}
func (n *node) applyTopology(t topology) {
	n.mu.RLock()
	// A push may have installed a newer view while a conditional request
	// was in flight. A version-only response must never replace that view.
	unchanged := t.Unchanged || (t.Version != "" && n.topologyVersion == t.Version)
	n.mu.RUnlock()
	if unchanged {
		// A network switch can remove OS routes without changing the
		// coordinator topology version.
		if n.tun != nil && n.c.autoTUN {
			if err := n.forceTUNRouteSync(); err != nil {
				n.logf("TUN route resync failed: %v", err)
			}
		}
		return
	}
	n.mu.Lock()
	n.dnsUpstream = t.DNSUpstream
	old := n.neighbors
	n.dir = map[string]*peer{}
	n.meshNodes = map[netip.Addr]string{}
	n.subnetRoutes = nil
	for _, v := range t.Directory {
		p := v
		n.dir[p.ID] = &p
		if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
			n.meshNodes[ip] = p.ID
		}
		for _, route := range p.Routes {
			virtual, e1 := netip.ParsePrefix(route.Virtual)
			lan, e2 := netip.ParsePrefix(route.LAN)
			if e1 == nil && e2 == nil && virtual.Addr().Is4() && virtual.Bits() == lan.Bits() {
				n.subnetRoutes = append(n.subnetRoutes, subnetRoute{virtual.Masked(), lan.Masked(), p.ID})
			}
		}
	}
	p := t.Self
	n.dir[p.ID] = &p
	if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
		n.meshNodes[ip] = p.ID
	}
	for _, route := range p.Routes {
		virtual, e1 := netip.ParsePrefix(route.Virtual)
		lan, e2 := netip.ParsePrefix(route.LAN)
		if e1 == nil && e2 == nil && virtual.Addr().Is4() && virtual.Bits() == lan.Bits() {
			n.subnetRoutes = append(n.subnetRoutes, subnetRoute{virtual.Masked(), lan.Masked(), p.ID})
		}
	}
	n.neighbors = map[string]*peer{}
	type lanHello struct {
		id   string
		addr *net.UDPAddr
	}
	lanHellos := make([]lanHello, 0, 2)
	lanHellosBase := len(lanHellos) // probe budget below counts only new candidates
	for _, v := range t.Neighbors {
		p := v
		p.discovered = time.Now()
		if q := old[p.ID]; q != nil {
			p.last = q.last
			p.lastRX = q.lastRX
			p.up = q.up
			p.discovered = q.discovered
			p.lastLAN = q.lastLAN
			p.lastLANRX = q.lastLANRX
			p.lastPathLAN = q.lastPathLAN
			p.lastLANProbe = q.lastLANProbe
			p.rttMS = q.rttMS
			p.lossEMA = q.lossEMA
		}
		// Coordinator-assisted LAN discovery: broadcasts cannot cross a
		// router, so a peer in an adjacent subnet of the same physical
		// network (cascaded routers) is probed by unicasting HELLO to the
		// LAN addresses it advertised. touch() flips the path to LAN only
		// when a reply actually arrives from a local address; a silent
		// candidate (segmentation, AP isolation, non-routable subnet) never
		// disturbs the working WAN path. On mobile data (no local LAN
		// subnet) probing is disabled entirely: the probes would leave
		// through the carrier network and never reach anyone.
		if len(v.LANAddrs) > 0 && n.hasLAN() {
			probedAt := time.Now()
			if probedAt.Sub(p.lastLANProbe) >= lanProbeInterval && !freshLAN(&p, probedAt) {
				p.lastLANProbe = probedAt
				for _, raw := range v.LANAddrs {
					if len(lanHellos)-lanHellosBase >= lanProbeMaxAddrs {
						break
					}
					addr, err := net.ResolveUDPAddr("udp4", raw)
					if err != nil || addr.IP == nil {
						continue
					}
					if !n.lanCandidateUsable(addr.IP) {
						continue
					}
					// Candidates equal to lastLAN are re-probed deliberately:
					// a peer that moved away and came back on the same address
					// must be re-found, and the interval above keeps the
					// retry cost at one small datagram per candidate.
					p.lastLAN = copyUDPAddr(addr)
					lanHellos = append(lanHellos, lanHello{id: p.ID, addr: copyUDPAddr(addr)})
				}
			}
		}
		if candidate := n.pendingLAN[p.ID]; candidate != nil {
			delete(n.pendingLAN, p.ID)
			// Candidate only: lastLANRX is confirmed by touch() once traffic
			// really arrives from the LAN address.
			p.lastLAN = candidate
			p.last = candidate
			lanHellos = append(lanHellos, lanHello{id: p.ID, addr: candidate})
		}
		n.neighbors[p.ID] = &p
	}
	n.links = t.Links
	n.firewall.Store(parseFirewallRules(t.Firewall))
	n.topologyVersion = t.Version
	n.mu.Unlock()
	// computeRoutes snapshots links/neighbors under its own brief read lock;
	// run it outside the write lock so it cannot deadlock on that RLock.
	routes, fallbacks := n.computeRoutes()
	n.mu.Lock()
	n.routes = routes
	n.altRoutes = fallbacks
	n.mu.Unlock()
	for _, hello := range lanHellos {
		n.logf("LAN endpoint candidate for %s: %s", hello.id[:8], hello.addr)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, hello.id, map[string]any{"public_key": n.id.Public}), hello.addr)
	}
	// The topology just changed: a new peer may sit on this very LAN (its
	// broadcasts may already have been missed while it was bootstrapping),
	// so announce immediately instead of waiting for the next tick.
	n.broadcastLANDiscovery()
	n.syncPortForwards(t.Forwards)
	n.cancelObsoleteSymmetricScans()
	if n.c.debug {
		n.mu.RLock()
		for _, r := range n.subnetRoutes {
			n.logf("virtual route %s -> %s (LAN %s)", r.Virtual, r.Owner, r.LAN)
		}
		n.mu.RUnlock()
	}
	if n.tun != nil && n.c.autoTUN {
		if err := n.syncTUNRoutes(); err != nil {
			n.logf("subnet route sync failed: %v", err)
		}
	}
	n.logf("topology=%s neighbors=%d", t.Version, len(t.Neighbors))
}
func tunnelKey(peer, id string) string { return peer + ":" + id }
func (n *node) syncPortForwards(rules []portForward) {
	n.forwardMu.Lock()
	n.forwardRules = map[int64]portForward{}
	for _, rule := range rules {
		n.forwardRules[rule.ID] = rule
	}
	n.forwardMu.Unlock()
	want := map[int64]portForward{}
	for _, rule := range rules {
		if rule.Source == n.id.ID {
			want[rule.ID] = rule
		}
	}
	n.forwardMu.Lock()
	for id, listener := range n.forwardListeners {
		if _, ok := want[id]; !ok {
			_ = listener.Close()
			delete(n.forwardListeners, id)
			n.logf("reverse forward %d stopped", id)
		}
	}
	for id, rule := range want {
		if _, ok := n.forwardListeners[id]; ok {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(rule.ListenHost, strconv.Itoa(rule.ListenPort)))
		if err != nil {
			n.logf("reverse forward %d cannot listen: %v", id, err)
			continue
		}
		n.forwardListeners[id] = listener
		go n.acceptPortForward(listener, rule)
		n.logf("reverse forward %s -> %s:%d via %s", listener.Addr(), rule.TargetHost, rule.TargetPort, rule.Target[:8])
	}
	n.forwardMu.Unlock()
}
func (n *node) acceptPortForward(listener net.Listener, rule portForward) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		go n.openTunnel(c, rule)
	}
}
func (n *node) openTunnel(c net.Conn, rule portForward) {
	id := protocol.NewPacket("", "", "", nil).ID
	n.forwardMu.Lock()
	n.tunnels[tunnelKey(rule.Target, id)] = c
	n.forwardMu.Unlock()
	defer n.closeTunnel(rule.Target, id)
	if !n.encrypted(rule.Target, "TUNNEL_OPEN", map[string]any{"id": id, "host": rule.TargetHost, "port": rule.TargetPort}, "") {
		return
	}
	n.copyTunnel(c, rule.Target, id)
}
func (n *node) copyTunnel(c net.Conn, peer, id string) {
	b := make([]byte, 900)
	for {
		count, err := c.Read(b)
		if count > 0 && !n.encrypted(peer, "TUNNEL_DATA", map[string]any{"id": id, "data": protocol.B64Encode(b[:count])}, "") {
			return
		}
		if err != nil {
			return
		}
	}
}
func (n *node) closeTunnel(peer, id string) {
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(peer, id)]
	delete(n.tunnels, tunnelKey(peer, id))
	n.forwardMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	_ = n.encrypted(peer, "TUNNEL_CLOSE", map[string]any{"id": id}, "")
}
func (n *node) tunnelOpen(src string, body map[string]any) {
	id, _ := body["id"].(string)
	host, _ := body["host"].(string)
	port, ok := body["port"].(float64)
	if id == "" || host == "" || !ok || port < 1 || port > 65535 {
		return
	}
	n.forwardMu.Lock()
	allowed := false
	for _, rule := range n.forwardRules {
		if rule.Source == src && rule.Target == n.id.ID && rule.TargetHost == host && rule.TargetPort == int(port) {
			allowed = true
			break
		}
	}
	n.forwardMu.Unlock()
	if !allowed {
		n.logf("rejected unauthorized reverse tunnel from %s", src[:8])
		return
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		n.encrypted(src, "TUNNEL_CLOSE", map[string]any{"id": id}, "")
		return
	}
	n.forwardMu.Lock()
	n.tunnels[tunnelKey(src, id)] = c
	n.forwardMu.Unlock()
	go func() { defer n.closeTunnel(src, id); n.copyTunnel(c, src, id) }()
}
func (n *node) tunnelData(src string, body map[string]any) {
	id, _ := body["id"].(string)
	encoded, _ := body["data"].(string)
	data, err := protocol.B64Decode(encoded)
	if id == "" || err != nil || len(data) > 900 {
		return
	}
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(src, id)]
	n.forwardMu.Unlock()
	if c != nil {
		_, _ = c.Write(data)
	}
}
func (n *node) tunnelClose(src string, body map[string]any) {
	id, _ := body["id"].(string)
	if id == "" {
		return
	}
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(src, id)]
	delete(n.tunnels, tunnelKey(src, id))
	n.forwardMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}


func parseFirewallRules(c *firewallConfig) *fwRules {
	if c == nil || c.Mode != "whitelist" {
		return nil
	}
	r := &fwRules{tcp: map[uint16]struct{}{}, udp: map[uint16]struct{}{}}
	for _, raw := range c.Ports {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		port, proto := entry, ""
		if i := strings.IndexByte(entry, '/'); i >= 0 {
			port, proto = entry[:i], entry[i+1:]
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		switch proto {
		case "tcp":
			r.tcp[uint16(n)] = struct{}{}
		case "udp":
			r.udp[uint16(n)] = struct{}{}
		case "":
			r.tcp[uint16(n)] = struct{}{}
			r.udp[uint16(n)] = struct{}{}
		}
	}
	return r
}
func (f *fwRules) permits(p []byte) bool {
	switch p[9] {
	case 1: // ICMP
		return true
	case 6, 17: // TCP, UDP
	default:
		return false
	}
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return false // non-first fragment: no port header to match
	}
	ihl := int(p[0]&15) * 4
	if ihl+4 > len(p) {
		return false
	}
	port := binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
	if p[9] == 6 {
		_, ok := f.tcp[port]
		return ok
	}
	_, ok := f.udp[port]
	return ok
}
func (n *node) ownerOf(ip netip.Addr) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if id := n.meshNodes[ip]; id != "" {
		return id
	}
	owner, bits := "", -1
	for _, route := range n.subnetRoutes {
		if route.Virtual.Contains(ip) && route.Virtual.Bits() > bits {
			owner, bits = route.Owner, route.Virtual.Bits()
		}
	}
	return owner
}
func (n *node) addressOwnedBy(owner string, ip netip.Addr) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.meshNodes[ip] == owner {
		return true
	}
	for _, route := range n.subnetRoutes {
		if route.Owner == owner && route.Virtual.Contains(ip) {
			return true
		}
	}
	return false
}
func (n *node) localMeshIP() netip.Addr {
	value := n.meshIPv4.Load()
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
func (n *node) isLocalMeshIP(ip netip.Addr) bool {
	return n.meshIPv4.Load() != 0 && ip == n.localMeshIP()
}
