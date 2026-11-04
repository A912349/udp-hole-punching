package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"
)

func (n *node) requestSymmetricScan(relayID, sessionID string) (proceed, coordinated bool) {
	waiter := make(chan struct{}, 1)
	n.symmetricMu.Lock()
	n.symmetricAckWaiters[sessionID] = waiter
	n.symmetricMu.Unlock()
	defer func() {
		n.symmetricMu.Lock()
		delete(n.symmetricAckWaiters, sessionID)
		n.symmetricMu.Unlock()
	}()

	err := n.request("POST", "/v1/symmetric-scan", map[string]any{
		"target_node_id": relayID,
		"session_id":     sessionID,
	}, &map[string]any{})
	if err != nil {
		// A 404 is the explicit compatibility signal from an older coordinator.
		// Retain the UDP-triggered handshake only for that deployment case.
		if strings.Contains(err.Error(), "status 404") {
			n.logf("coordinator has no symmetric rendezvous API; using legacy UDP trigger")
			return true, false
		}
		n.logf("symmetric rendezvous request failed: %v", err)
		return false, false
	}
	n.logf("symmetric rendezvous requested from %s; waiting for scan ACK", relayID[:8])
	select {
	case <-waiter:
		n.logf("symmetric scan ACK received from %s", relayID[:8])
		return true, true
	case <-time.After(10 * time.Second):
		n.logf("symmetric rendezvous timed out waiting for scan ACK from %s", relayID[:8])
		return false, true
	}
}
func (n *node) symmetricRelays() []symmetricRelayTarget {
	n.mu.RLock()
	relays := make([]symmetricRelayTarget, 0, len(n.neighbors))
	for id, candidate := range n.neighbors {
		if candidate.Role == "superpeer" {
			relays = append(relays, symmetricRelayTarget{id: id, peer: *candidate})
		}
	}
	n.mu.RUnlock()
	sort.Slice(relays, func(i, j int) bool { return relays[i].id < relays[j].id })
	return relays
}
func (n *node) symmetricRelay() (string, *peer) {
	relays := n.symmetricRelays()
	if len(relays) == 0 {
		return "", nil
	}
	return relays[0].id, &relays[0].peer
}
func (n *node) symmetricTransportReady(relayID string) bool {
	n.symmetricConnMu.RLock()
	_, ready := n.symmetricConns[relayID]
	n.symmetricConnMu.RUnlock()
	return ready
}
func (n *node) symmetricTransportCount() int {
	n.symmetricConnMu.RLock()
	count := len(n.symmetricConns)
	n.symmetricConnMu.RUnlock()
	return count
}
func (n *node) installSymmetricConn(relayID string, next *net.UDPConn) bool {
	n.symmetricConnMu.Lock()
	primary := len(n.symmetricConns) == 0
	n.symmetricConns[relayID] = next
	n.symmetricConnMu.Unlock()
	n.symmetricMu.Lock()
	n.symmetricReady = true
	n.symmetricMu.Unlock()
	if primary {
		n.replaceUDPConn(next)
	}
	n.addReceiveSocket(next)
	return primary
}
func (n *node) currentUDPConn() *net.UDPConn {
	n.connMu.RLock()
	defer n.connMu.RUnlock()
	return n.conn
}
func (n *node) connForPeer(peerID string) *net.UDPConn {
	if n.c.nat == "symmetric" {
		n.symmetricConnMu.RLock()
		conn := n.symmetricConns[peerID]
		n.symmetricConnMu.RUnlock()
		if conn != nil {
			return conn
		}
	}
	return n.currentUDPConn()
}
func (n *node) replaceUDPConn(next *net.UDPConn) {
	n.connMu.Lock()
	old := n.conn
	n.conn = next
	n.connMu.Unlock()
	n.finishUDPConnReplacement(old, next)
	n.addReceiveSocket(next)
}
func resolveBindIface(configured string) string {
	switch configured {
	case "none":
		return ""
	case "auto":
		return defaultRouteInterfaceFn()
	case "":
		if !androidRuntimeFn() {
			return ""
		}
		return defaultRouteInterfaceFn()
	default:
		return configured
	}
}
func (n *node) rebindUDPConn() error {
	// Do not close a socket while receive or STUN is using it. Receive loops
	// hold a shared lock, so all per-superpeer sockets can read concurrently
	// while rebind still waits for them to leave their one-second read window.
	n.udpReadMu.Lock()
	defer n.udpReadMu.Unlock()

	n.connMu.Lock()
	old := n.conn
	if old == nil {
		n.connMu.Unlock()
		return errors.New("UDP socket is not initialized")
	}
	oldAddr, ok := old.LocalAddr().(*net.UDPAddr)
	if !ok {
		n.connMu.Unlock()
		return errors.New("UDP socket has an invalid local address")
	}
	port := oldAddr.Port
	_ = old.Close()
	bind, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", n.c.bind, port))
	if err != nil {
		n.connMu.Unlock()
		return err
	}
	next, err := net.ListenUDP("udp4", bind)
	if err != nil {
		// If the original port was ephemeral, retaining it is not meaningful.
		// A fresh ephemeral port is preferable to leaving the node offline.
		if n.c.port == 0 {
			next, err = net.ListenUDP("udp4", &net.UDPAddr{IP: bind.IP})
		}
	}
	if err != nil {
		n.connMu.Unlock()
		return err
	}
	configureUDPSocket(next)
	// Re-resolve on every rebind: "auto" follows the network (wlan0 <->
	// rmnet_data1) after roaming. Bump the generation first so in-flight
	// symmetric bursts detect that their sockets are now stale.
	n.networkGen.Add(1)
	if iface := resolveBindIface(n.c.bindIface); iface != "" {
		if err := bindUDPInterface(next, iface); err != nil {
			n.logf("UDP bind to interface %s failed: %v (using wildcard socket)", iface, err)
		}
	}
	n.conn = next
	n.connMu.Unlock()
	n.finishUDPConnReplacement(old, next)
	n.addReceiveSocket(next)
	return nil
}
func (n *node) finishUDPConnReplacement(old, next *net.UDPConn) {
	oldPort := 0
	if old != nil {
		oldPort = old.LocalAddr().(*net.UDPAddr).Port
		_ = old.Close()
	}
	if n.stop != nil && runtime.GOOS == "windows" {
		newPort := next.LocalAddr().(*net.UDPAddr).Port
		if oldPort != 0 {
			cleanupPlatformNetwork(oldPort)
		}
		if err := configurePlatformNetwork(newPort); err != nil {
			n.logf("Windows firewall update for recovered UDP port %d failed: %v", newPort, err)
		}
	}
}
func (n *node) awaitSymmetricHello(conn *net.UDPConn, relayID, sessionID string, responses chan<- symmetricReply) {
	_ = conn.SetReadDeadline(time.Now().Add(symmetricBurstTimeout))
	buffer := make([]byte, 65535)
	length, address, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return
	}
	packet, err := protocol.DecodePacket(buffer[:length], n.key)
	if err != nil || packet.Type != "HELLO" || packet.Source != relayID || packet.Destination != n.id.ID || payloadString(packet, "session_id") != sessionID {
		return
	}
	select {
	case responses <- symmetricReply{conn: conn, addr: address}:
	default:
	}
}
func (n *node) startSymmetricScan(peerID, endpoint, sessionID string, force bool) {
	n.mu.RLock()
	peer := n.neighbors[peerID]
	live := n.usable(peer)
	n.mu.RUnlock()

	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()

	if existing := n.symmetricScans[peerID]; existing != nil {
		if !force && n.symmetricSessions[peerID] == sessionID {
			return
		}
		delete(n.symmetricScans, peerID)
		delete(n.symmetricSessions, peerID)
		close(existing)
	}

	if !live {
		delete(n.symmetricConnected, peerID)
	}

	if n.symmetricConnected[peerID] && !force {
		return
	}

	cancel := make(chan struct{})
	n.symmetricScans[peerID] = cancel
	n.symmetricSessions[peerID] = sessionID
	go n.scanSymmetricNeighbor(peerID, endpoint, sessionID, cancel)
}
func (n *node) scanSymmetricNeighbor(peerID, endpoint, sessionID string, cancel chan struct{}) {
	// A full symmetric-NAT port scan is intentionally broad. Bound concurrent
	// scans so several newly discovered peers cannot monopolize CPU and UDP
	// bandwidth at once; queued scans remain cancellable by a newer topology.
	if n.symmetricScanSlots != nil {
		select {
		case n.symmetricScanSlots <- struct{}{}:
			defer func() { <-n.symmetricScanSlots }()
		case <-cancel:
			return
		}
	}
	defer func() {
		n.symmetricMu.Lock()
		if n.symmetricScans[peerID] == cancel {
			delete(n.symmetricScans, peerID)
			delete(n.symmetricSessions, peerID)
		}
		n.symmetricMu.Unlock()
	}()
	deadline := time.Now().Add(symmetricBurstTimeout - symmetricRetryDelay)
	address, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		n.logf("symmetric scan endpoint for %s: %v", peerID[:8], err)
		return
	}
	step := n.c.symmetricScanStep
	if step == 0 {
		step = symmetricScanDefaultStep
	}
	n.logf("symmetric scan for %s around %s (port interval %d)", peerID[:8], endpoint, step)
	symmetricScanPorts(address.Port, step, func(port int) bool {
		if n.symmetricScanCancelled(cancel) {
			return false
		}
		if time.Now().After(deadline) {
			n.logf("symmetric scan window expired for %s", peerID[:8])
			return false
		}
		target := *address
		target.Port = port
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, peerID, map[string]any{"public_key": n.id.Public, "session_id": sessionID}), &target)
		time.Sleep(scanDelay)
		return true
	})
}
func symmetricScanPorts(center, step int, visit func(port int) bool) {
	if center < 1 || center > maxUDPPort || step < 1 || step > maxUDPPort {
		return
	}
	for offset := 0; offset < step; offset++ {
		passCenter := center - offset
		if !symmetricScanPortPass(passCenter, step, visit) {
			return
		}
	}
}
func (n *node) peerKey(id string) ([]byte, *peer, error) {
	cached, p, e := n.peerCrypto(id)
	return cached.key, p, e
}

// peerCrypto returns the cached AEAD material for a peer under a single read
// lock. The common fast path -- an entry that still matches the peer's current
// public key -- holds n.mu.RLock() exactly once; the symmetric-key derivation
// and write-lock only happen on a cache miss. This collapses the two RLocks that
// peerAEAD/peerCipher previously took (one inside peerKey to read the key, one
// again to read the entry) into one lookup per packet.
func (n *node) peerCrypto(id string) (cachedKey, *peer, error) {
	n.mu.RLock()
	p := n.dir[id]
	if cached, ok := n.sharedKeys[id]; ok && cached.public == p.Public {
		n.mu.RUnlock()
		return cached, p, nil
	}
	n.mu.RUnlock()
	var cached cachedKey
	if p == nil {
		return cached, nil, errors.New("unknown peer")
	}
	k, e := protocol.SharedKey(n.id.Private, p.Public)
	if e == nil {
		decodedID, decodeErr := hex.DecodeString(id)
		if decodeErr != nil || len(decodedID) != 16 {
			return cached, nil, errors.New("peer has an invalid node ID")
		}
		var peerID [16]byte
		copy(peerID[:], decodedID)
		aead, cipherErr := protocol.NewAEAD(k)
		if cipherErr != nil {
			return cached, nil, cipherErr
		}
		nonces, nonceErr := protocol.NewNonceSequence()
		if nonceErr != nil {
			return cached, nil, nonceErr
		}
		n.mu.Lock()

		n.sharedKeys[id] = cachedKey{
			public: p.Public, key: k, aead: aead, nonces: nonces, peerID: peerID,
			openAAD:  []byte(id + ":" + n.id.ID),
			sealAAD:  []byte(n.id.ID + ":" + id),
			hexCache: hexCache{selfHex: n.id.ID, peerHex: id}, // pre-computed for fast path
		}
		cached = n.sharedKeys[id]
		n.mu.Unlock()
	}
	return cached, p, e
}
func (n *node) peerAEAD(id string) (cipher.AEAD, []byte, error) {
	cached, _, e := n.peerCrypto(id)
	if e != nil {
		return nil, nil, e
	}
	if cached.aead == nil {
		return nil, nil, errors.New("missing peer cipher")
	}
	return cached.aead, cached.openAAD, nil
}
func (n *node) peerCipher(id string) (cipher.AEAD, *protocol.NonceSequence, []byte, [16]byte, error) {
	cached, _, e := n.peerCrypto(id)
	if e != nil {
		return nil, nil, nil, [16]byte{}, e
	}
	if cached.aead == nil || cached.nonces == nil {
		return nil, nil, nil, [16]byte{}, errors.New("missing peer cipher")
	}
	return cached.aead, cached.nonces, cached.sealAAD, cached.peerID, nil
}

func (n *node) encrypted(dst, typ string, body map[string]any, id string) bool {
	k, _, e := n.peerKey(dst)
	if e != nil {
		return false
	}
	raw, _ := json.Marshal(map[string]any{"type": typ, "body": body})
	s, e := protocol.Seal(k, raw, []byte(n.id.ID+":"+dst))
	if e != nil {
		return false
	}
	p := protocol.NewPacket("DATA", n.id.ID, dst, map[string]any{"sealed": s})
	if id != "" {
		p.ID = id
	}
	return n.send(p)
}
func (n *node) handleLegacyIPFragment(source string, sealed map[string]string) {
	key, _, err := n.peerKey(source)
	if err != nil {
		return
	}
	plain, err := protocol.Open(key, sealed, []byte(source+":"+n.id.ID))
	if err != nil {
		return
	}
	n.acceptIPFragment(source, plain)
}
func (n *node) acceptIPFragment(source string, plain []byte) {
	// The current sender emits one fragment for every packet up to maxTUN.
	// Avoid a mutex, a clock read, reassembly bookkeeping and a goroutine per
	// packet on this overwhelmingly common path.
	if len(plain) >= 12 && binary.BigEndian.Uint16(plain[8:10]) == 0 && binary.BigEndian.Uint16(plain[10:12]) == 1 {
		n.enqueueDeliver(source, plain[12:])
		return
	}
	n.acceptIPFragmentAt(source, plain, time.Now())
}
func (n *node) acceptIPFragmentAt(source string, plain []byte, now time.Time) {
	if len(plain) < 12 || len(plain)-12 > maxTUN {
		return
	}
	fragmentID := plain[:8]
	index := binary.BigEndian.Uint16(plain[8:10])
	count := binary.BigEndian.Uint16(plain[10:12])
	if count == 0 || count > 128 || index >= count {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	cutoff := now.Add(-10 * time.Second)
	for id, state := range n.reassembly {
		if state.receivedAt.Before(cutoff) {
			delete(n.reassembly, id)
		}
	}
	stateID := source + ":" + hex.EncodeToString(fragmentID)
	state := n.reassembly[stateID]
	if state == nil {
		if len(n.reassembly) >= 128 {
			for id := range n.reassembly {
				delete(n.reassembly, id)
				break
			}
		}
		state = &reassembly{count: count, chunks: map[uint16][]byte{}}
		n.reassembly[stateID] = state
	}
	if state.count != count {
		delete(n.reassembly, stateID)
		return
	}
	if _, exists := state.chunks[index]; exists {
		// First authenticated fragment wins. Duplicates neither allocate nor
		// keep an incomplete assembly alive indefinitely.
		return
	}
	if len(plain)-12 > maxTUN-state.totalBytes {
		delete(n.reassembly, stateID)
		return
	}
	state.chunks[index] = append([]byte(nil), plain[12:]...)
	state.totalBytes += len(plain) - 12
	state.receivedAt = now
	if len(state.chunks) != int(count) {
		return
	}
	packet := make([]byte, 0, state.totalBytes)
	for part := uint16(0); part < count; part++ {
		chunk, ok := state.chunks[part]
		if !ok {
			return
		}
		packet = append(packet, chunk...)
	}
	delete(n.reassembly, stateID)
	n.enqueueDeliver(source, packet)
}

// hexDigits is a pre-computed lookup table for converting bytes to their
// two-character hexadecimal representation. This avoids calling hex.EncodeToString
// on every received packet in the fast path.
var hexDigits [256][2]byte // 256*2 = 512 bytes, all L1 cache friendly

func init() {
	const hex = "0123456789abcdef"
	for i := range hexDigits {
		hexDigits[i][0] = hex[(i>>4)&0xf]
		hexDigits[i][1] = hex[i&0xf]
	}
}

// bytesToHex16 converts a 16-byte slice to its 32-character hex representation.
// This is ~5x faster than hex.EncodeToString and avoids heap allocation when
// writing into caller-owned storage. It assumes dst has exactly 32 bytes capacity.
func bytesToHex16(dst []byte, src [16]byte) {
	for i := range src {
		dst[i*2] = hexDigits[src[i]][0]
		dst[i*2+1] = hexDigits[src[i]][1]
	}
}

func fastAAD(dst, peerAAD, packetID []byte) []byte {
	dst = append(dst, peerAAD...)
	return append(dst, packetID...)
}
func (n *node) fast(data []byte, a *net.UDPAddr) {
	if len(data) < fastHeader+28 || len(data) > maxFastFrame {
		n.debugf("drop fast frame from %s: invalid size (%d bytes)", a, len(data))
		return
	}
	ttl := int(data[4])
	// Pre-allocate hex buffers on the stack — no heap allocation per packet.
	var srcHex [32]byte
	bytesToHex16(srcHex[:], *(*[16]byte)(data[5:21]))
	var packetID [12]byte
	copy(packetID[:], data[37:49])
	if ttl < 1 || ttl > protocol.DefaultTTL {
		n.debugf("drop fast frame from %s: invalid TTL or duplicate", srcHex[:8])
		return
	}
	// Control packets refresh the endpoint and liveness. Updating it on every
	// data packet only adds a contended lock and a clock read to the fast path.
	if !bytes.Equal(data[21:37], n.idBinary[:]) {
		var dstHex [32]byte
		bytesToHex16(dstHex[:], *(*[16]byte)(data[21:37]))
		if n.c.role == "superpeer" && ttl > 1 && n.rememberFast(packetID) {
			// Only duplicate suppression is possible here, not authentication.
			data[4]--
			n.sendFast(string(dstHex[:]), data)
		}
		return
	}
	aead, aad, e := n.peerAEAD(string(srcHex[:]))
	if e != nil {
		n.debugf("drop fast frame from %s: %v", srcHex[:8], e)
		return
	}
	var aadBuffer [77]byte // 32-byte hex IDs + ':' + 12-byte packet ID
	plain, e := protocol.OpenBytesWithAEAD(aead, data[fastHeader:], fastAAD(aadBuffer[:0], aad, packetID[:]))
	if e != nil {
		n.debugf("drop fast frame from %s: decrypt failed: %v", srcHex[:8], e)
		return
	}
	if !n.rememberFast(packetID) {
		return
	}
	n.debugf("fast frame from %s received (%d bytes encrypted)", srcHex[:8], len(data))
	n.acceptIPFragment(string(srcHex[:]), plain)
}
func (n *node) sendFast(dst string, data []byte) bool {
	return n.sendFastMode(dst, data, false)
}
func (n *node) sendFastMode(dst string, data []byte, wait bool) bool {
	_, p := n.nextHop(dst)
	if !n.usable(p) {
		_, p = n.fallbackHop(dst)
	}
	if !n.usable(p) {
		n.debugf("fast send to %s: no usable route", dst[:8])
		return false
	}
	a := p.last
	if a == nil {
		var e error
		a, e = net.ResolveUDPAddr("udp", p.Endpoint)
		if e != nil {
			n.debugf("fast send to %s: invalid endpoint %q: %v", dst[:8], p.Endpoint, e)
			return false
		}
	}
	conn := n.connForPeer(p.ID)
	address := a.(*net.UDPAddr)
	if n.udpSendQueue == nil {
		_, e := conn.WriteToUDP(data, address)
		return e == nil
	}
	owned := n.udpSendPool.Get().([]byte)[:len(data)]
	copy(owned, data)
	return n.enqueueUDP(outboundDatagram{conn: conn, data: owned, address: address}, wait)
}
func (n *node) isTUNBroadcast(addr netip.Addr) bool {
	if addr == ipv4LimitedBroadcast {
		return true
	}
	if n.meshIPv4.Load() == 0 || n.c.prefix < 0 || n.c.prefix > 30 {
		return false
	}
	local := n.localMeshIP()
	prefix := netip.PrefixFrom(local, n.c.prefix).Masked()
	if !prefix.Contains(addr) {
		return false
	}
	base, value := prefix.Addr().As4(), addr.As4()
	for bit := n.c.prefix; bit < 32; bit++ {
		byteIndex, mask := bit/8, byte(1<<(7-bit%8))
		if value[byteIndex]&mask == 0 || base[byteIndex]&mask != 0 {
			return false
		}
	}
	return true
}
func packetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func adjustAddressChecksum(field []byte, old, new [4]byte) {
	sum := uint32(^binary.BigEndian.Uint16(field))
	for i := 0; i < 4; i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(old[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(new[i : i+2]))
		sum = (sum & 0xffff) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	binary.BigEndian.PutUint16(field, ^uint16(sum))
}
func (n *node) syncTUNRoutes() error {
	n.routeMu.Lock()
	defer n.routeMu.Unlock()
	n.mu.RLock()
	wanted := map[string]bool{}
	localLAN, remoteVirtual := []string{}, []string{}
	if meshIP, err := netip.ParseAddr(n.c.meshIP); err == nil {
		remoteVirtual = append(remoteVirtual, netip.PrefixFrom(meshIP, n.c.prefix).Masked().String())
	}
	for _, r := range n.subnetRoutes {
		wanted[r.Virtual.String()] = true
		if r.Owner == n.id.ID {
			localLAN = append(localLAN, r.LAN.String())
		} else {
			remoteVirtual = append(remoteVirtual, r.Virtual.String())
		}
	}
	n.mu.RUnlock()
	if err := configureTUNRoutes(n.c.tun, wanted, n.installedRoutes, n.tunLUID); err != nil {
		return err
	}
	n.installedRoutes = wanted
	if err := configureSiteNAT(localLAN, remoteVirtual); err != nil {
		n.logf("automatic site NAT unavailable: %v", err)
	}
	n.logf("TUN virtual routes synchronized: %d", len(wanted))
	return nil
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
