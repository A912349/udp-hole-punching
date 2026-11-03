package main

import (
	"io"
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
				routes, fallbacks := n.computeRoutes()
				n.mu.Lock()
				n.routes = routes
				n.altRoutes = fallbacks
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
func (n *node) tunLoop(ctx context.Context) {
	n.logf("TUN reader started")
	// Read a complete native packet before applying the overlay MTU policy.
	// Windows/Wintun can otherwise return io.ErrShortBuffer for a normal
	// 1500-byte host packet and permanently stop the TUN loop.
	b := make([]byte, 64<<10)
	for {
		l, e := readTUN(n.tun, b)
		if e != nil {
			if errors.Is(e, io.ErrShortBuffer) {
				n.debugf("drop oversized TUN frame")
				continue
			}
			if ctx.Err() == nil {
				n.logf("TUN read failed: %v", e)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		if l < 20 || l > maxTUN || b[0]>>4 != 4 {
			n.debugf("drop TUN frame: invalid IPv4 or exceeds MTU (%d bytes)", l)
			continue
		}
		srcAddr := netip.AddrFrom4([4]byte(b[12:16]))
		dstAddr := netip.AddrFrom4([4]byte(b[16:20]))
		if n.isTUNBroadcast(dstAddr) {
			continue
		}
		// The TUN carries the whole mesh subnet, including this node's own
		// address. Do not look up a peer for a packet addressed to ourselves:
		// inject it back into the kernel so the local IP stack receives it.
		if n.isLocalMeshIP(dstAddr) {
			if !n.loopbackTUNPacket(b[:l]) && n.c.debug {
				n.debugf("TUN IPv4 %s -> %s: loopback failed", srcAddr, dstAddr)
			}
			continue
		}
		dst := n.ownerOf(dstAddr)
		if dst == "" {
			if n.c.debug {
				n.debugf("drop TUN frame: no node owns %s", dstAddr)
			}
			continue
		}
		if dst == n.id.ID {
			// The local virtual route is also installed on the TUN. Translate
			// it back to the physical LAN and inject it into the kernel.
			if n.translateLocalPacket(b[:l], false) {
				_, _ = n.tun.Write(b[:l])
			}
			continue
		}
		if !n.isLocalMeshIP(srcAddr) && !n.translateLocalPacket(b[:l], true) {
			if n.c.debug {
				n.debugf("drop TUN frame: source %s is not local mesh IP", srcAddr)
			}
			continue
		}
		if n.c.debug {
			n.debugf("TUN IPv4 %s -> %s (%d bytes)", srcAddr, dstAddr, l)
		}
		if !n.sendIP(dst, b[:l]) {
			if n.c.debug {
				n.debugf("TUN IPv4 %s -> %s: send failed", srcAddr, dstAddr)
			}
		}
	}
}
func (n *node) loopbackTUNPacket(packet []byte) bool {
	if n.tun == nil {
		return false
	}
	if _, err := writeTUN(n.tun, packet); err != nil {
		n.debugf("TUN loopback failed: %v", err)
		return false
	}
	return true
}
func (n *node) sendIP(dst string, p []byte) bool {
	if len(p) > maxTUN {
		return false
	}
	aead, nonces, aad, target, e := n.peerCipher(dst)
	if e != nil {
		n.debugf("IP send to %s: %v", dst[:8], e)
		return false
	}
	var packetID [12]byte
	if !n.nextPacketID(packetID[:]) {
		n.debugf("IP send to %s: packet ID sequence exhausted", dst[:8])
		return false
	}

	// Build header, nonce and plaintext in one backing array. Seal appends its
	// output exactly over the plaintext region, which is an overlap supported by
	// cipher.AEAD. The existing end-to-end tag binds the packet ID and peer
	// IDs. TTL remains mutable so relays can decrement it without re-sealing.
	nonceSize := aead.NonceSize()
	plainAt := fastHeader + nonceSize
	plainSize := 12 + len(p)
	buffer := n.sendPool.Get().([]byte)
	defer n.sendPool.Put(buffer[:maxFastFrame])
	pkt := buffer[:plainAt+plainSize]
	copy(pkt, fastMagic)
	pkt[4] = protocol.DefaultTTL
	copy(pkt[5:21], n.idBinary[:])
	copy(pkt[21:37], target[:])
	copy(pkt[37:49], packetID[:])
	if e = nonces.NextInto(pkt[fastHeader:plainAt]); e != nil {
		return false
	}
	// Fragment ID and index remain zero. Count=1 takes the receiver's optimized
	// no-reassembly path, so a random fragment ID has no observable purpose.
	clear(pkt[plainAt : plainAt+12])
	binary.BigEndian.PutUint16(pkt[plainAt+10:plainAt+12], 1)
	copy(pkt[plainAt+12:], p)
	var aadBuffer [77]byte
	pkt = aead.Seal(pkt[:plainAt], pkt[fastHeader:plainAt], pkt[plainAt:], fastAAD(aadBuffer[:0], aad, packetID[:]))
	// Local TUN traffic can apply backpressure to the kernel rather than
	// discard encrypted packets when the UDP sender momentarily falls behind.
	// Relay traffic still uses the nonblocking sendFast path.
	return n.sendFastMode(dst, pkt, true)
}
func (n *node) deliver(src string, p []byte) {
	if n.tun == nil || len(p) < 20 || len(p) > maxTUN || p[0]>>4 != 4 {
		n.debugf("drop IP packet from %s: invalid packet or TUN disabled", src[:8])
		return
	}
	sourceIP, destinationIP := netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
	if n.c.debug {
		n.debugf("deliver candidate from %s: %s -> %s proto=%d", src[:8], sourceIP, destinationIP, p[9])
	}
	localDestination := n.isLocalMeshIP(destinationIP)
	if !n.addressOwnedBy(src, sourceIP) || !(localDestination || n.addressOwnedBy(n.id.ID, destinationIP)) {
		n.debugf("drop IP packet from %s: address ownership check failed", src[:8])
		return
	}
	if localDestination {
		// Coordinator-managed mesh firewall. Nil rules mean allow-all, so the
		// default-mode cost is one atomic load per packet; whitelist mode adds
		// a protocol check, a fragment-offset test and one small map lookup.
		if fw := n.firewall.Load(); fw != nil && !fw.permits(p) {
			n.debugf("firewall drop from %s: proto %d not permitted", src[:8], p[9])
			return
		}
	}
	if !localDestination && !n.translateLocalPacket(p, false) {
		n.debugf("drop IP packet from %s: missing local translation", src[:8])
		return
	}
	if n.c.debug {
		n.debugf("deliver to TUN from %s: %s -> %s", src[:8], netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])))
		ihl := int(p[0]&15) * 4
		if ihl <= len(p) && packetChecksum(p[:ihl]) != 0 {
			n.debugf("deliver warning: invalid IPv4 header checksum")
		}
	}
	if _, err := writeTUN(n.tun, p); err != nil {
		n.debugf("deliver IP packet from %s failed: %v", src[:8], err)
		return
	}
	n.stats.deliveredPackets.Add(1)
	n.stats.deliveredBytes.Add(uint64(len(p)))
	n.debugf("TUN IPv4 delivered from %s (%d bytes)", src[:8], len(p))
}
func (n *node) translateLocalPacket(packet []byte, source bool) bool {
	if len(packet) < 20 {
		return false
	}
	at := 16
	if source {
		at = 12
	}
	ip := netip.AddrFrom4([4]byte(packet[at : at+4]))
	n.mu.RLock()
	var from, to netip.Prefix
	for _, r := range n.subnetRoutes {
		if r.Owner != n.id.ID {
			continue
		}
		candidateFrom, candidateTo := r.Virtual, r.LAN
		if source {
			candidateFrom, candidateTo = r.LAN, r.Virtual
		}
		if candidateFrom.Contains(ip) {
			from, to = candidateFrom, candidateTo
			break
		}
	}
	n.mu.RUnlock()
	if !from.IsValid() {
		return false
	}
	a := ip.As4()
	b := from.Addr().As4()
	c := to.Addr().As4()
	offset := binary.BigEndian.Uint32(a[:]) - binary.BigEndian.Uint32(b[:])
	var replacement [4]byte
	binary.BigEndian.PutUint32(replacement[:], binary.BigEndian.Uint32(c[:])+offset)
	old := [4]byte(packet[at : at+4])
	copy(packet[at:at+4], replacement[:])
	adjustAddressChecksum(packet[10:12], old, replacement)
	ihl := int(packet[0]&15) * 4
	if ihl > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
		return true
	}
	switch packet[9] {
	case 6:
		if ihl+18 <= len(packet) {
			adjustAddressChecksum(packet[ihl+16:ihl+18], old, replacement)
		}
	case 17:
		if ihl+8 <= len(packet) && binary.BigEndian.Uint16(packet[ihl+6:ihl+8]) != 0 {
			adjustAddressChecksum(packet[ihl+6:ihl+8], old, replacement)
		}
	}
	return true
}
