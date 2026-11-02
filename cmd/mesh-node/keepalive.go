package main

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	_ "net/http/pprof"
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
	n.mu.RLock()
	p := n.dir[id]
	if p != nil {
		if cached, ok := n.sharedKeys[id]; ok && cached.public == p.Public {
			n.mu.RUnlock()
			return cached.key, p, nil
		}
	}
	n.mu.RUnlock()
	if p == nil {
		return nil, nil, errors.New("unknown peer")
	}
	k, e := protocol.SharedKey(n.id.Private, p.Public)
	if e == nil {
		decodedID, decodeErr := hex.DecodeString(id)
		if decodeErr != nil || len(decodedID) != 16 {
			return nil, nil, errors.New("peer has an invalid node ID")
		}
		var peerID [16]byte
		copy(peerID[:], decodedID)
		aead, cipherErr := protocol.NewAEAD(k)
		if cipherErr != nil {
			return nil, nil, cipherErr
		}
		nonces, nonceErr := protocol.NewNonceSequence()
		if nonceErr != nil {
			return nil, nil, nonceErr
		}
		n.mu.Lock()
		n.sharedKeys[id] = cachedKey{public: p.Public, key: k, aead: aead, nonces: nonces, peerID: peerID, openAAD: []byte(id + ":" + n.id.ID), sealAAD: []byte(n.id.ID + ":" + id)}
		n.mu.Unlock()
	}
	return k, p, e
}
func (n *node) peerAEAD(id string) (cipher.AEAD, []byte, error) {
	if _, _, err := n.peerKey(id); err != nil {
		return nil, nil, err
	}
	n.mu.RLock()
	cached, ok := n.sharedKeys[id]
	n.mu.RUnlock()
	if !ok || cached.aead == nil {
		return nil, nil, errors.New("missing peer cipher")
	}
	return cached.aead, cached.openAAD, nil
}
func (n *node) peerCipher(id string) (cipher.AEAD, *protocol.NonceSequence, []byte, [16]byte, error) {
	if _, _, err := n.peerKey(id); err != nil {
		return nil, nil, nil, [16]byte{}, err
	}
	n.mu.RLock()
	cached, ok := n.sharedKeys[id]
	n.mu.RUnlock()
	if !ok || cached.aead == nil || cached.nonces == nil {
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
func (n *node) resolve(value string) (string, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.dir[value] != nil {
		return value, nil
	}
	var a []string
	for id := range n.dir {
		if strings.HasPrefix(id, value) {
			a = append(a, id)
		}
	}
	if len(a) == 1 {
		return a[0], nil
	}
	return "", errors.New("unknown or ambiguous node ID")
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
	src := hex.EncodeToString(data[5:21])
	var packetID [12]byte
	copy(packetID[:], data[37:49])
	if ttl < 1 || ttl > protocol.DefaultTTL {
		n.debugf("drop fast frame from %s: invalid TTL or duplicate", src[:8])
		return
	}
	// Control packets refresh the endpoint and liveness. Updating it on every
	// data packet only adds a contended lock and a clock read to the fast path.
	if !bytes.Equal(data[21:37], n.idBinary[:]) {
		dst := hex.EncodeToString(data[21:37])
		if n.c.role == "superpeer" && ttl > 1 && n.rememberFast(packetID) {
			// Only duplicate suppression is possible here, not authentication.
			data[4]--
			n.sendFast(dst, data)
		}
		return
	}
	aead, aad, e := n.peerAEAD(src)
	if e != nil {
		n.debugf("drop fast frame from %s: %v", src[:8], e)
		return
	}
	var aadBuffer [77]byte // 32-byte hex IDs + ':' + 12-byte packet ID
	plain, e := protocol.OpenBytesWithAEAD(aead, data[fastHeader:], fastAAD(aadBuffer[:0], aad, packetID[:]))
	if e != nil {
		n.debugf("drop fast frame from %s: decrypt failed: %v", src[:8], e)
		return
	}
	if !n.rememberFast(packetID) {
		return
	}
	n.debugf("fast frame from %s received (%d bytes encrypted)", src[:8], len(data))
	n.acceptIPFragment(src, plain)
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
