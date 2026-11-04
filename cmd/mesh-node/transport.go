package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

)

func (n *node) refreshEndpointAttempt(attempt int) {
	if !n.recoveryMu.TryLock() {
		// A full recovery pass is in flight. Returning silently here used to
		// discard the fastest path to a fresh endpoint whenever recoverNetwork
		// happened to hold the lock; schedule a short bounded retry instead.
		if attempt < endpointRefreshRetries {
			time.AfterFunc(time.Second, func() { n.refreshEndpointAttempt(attempt) })
		}
		return
	}
	defer n.recoveryMu.Unlock()
	retry := func(stage string, err error) {
		n.logf("control reconnect: %s: %v", stage, err)
		if attempt < endpointRefreshRetries {
			time.AfterFunc(endpointRefreshRetryDelay, func() {
				n.refreshEndpointAttempt(attempt + 1)
			})
		}
	}
	if err := n.rebindUDPConn(); err != nil {
		retry("UDP rebind failed", err)
		return
	}
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		retry("STUN check failed", err)
		return
	}
	if endpoint == n.c.endpoint {
		return
	}
	n.applyEndpointChange(n.c.endpoint, endpoint, nat, "control reconnect")
}
func (n *node) verifyEndpoint() {
	if n.c.endpoint == "" {
		return
	}
	if !n.recoveryMu.TryLock() {
		// A recovery or refresh pass is running; it already re-detects the
		// endpoint. Skip this tick instead of queueing a retry.
		return
	}
	defer n.recoveryMu.Unlock()
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		n.logf("endpoint verify: STUN check failed: %v", err)
		return
	}
	if endpoint == n.c.endpoint {
		return
	}
	n.applyEndpointChange(n.c.endpoint, endpoint, nat, "endpoint verify")
}
func (n *node) applyEndpointChange(previous, endpoint, nat, source string) {
	n.logf("%s: UDP endpoint changed %s -> %s", source, previous, endpoint)
	if !endpointIPChanged(previous, endpoint) {
		n.c.endpoint = endpoint
		if n.requestedNAT == "auto" {
			n.c.nat = nat
		}
		// helloAll deliberately skips peers that still look usable, but a NAT
		// rebind invalidated exactly those paths: they point at the dead
		// mapping. A ping round through the new socket lets every peer
		// relearn the source port at once instead of waiting up to a whole
		// keepalive interval (mobile NAT mappings are short-lived).
		n.helloAll()
		n.pingAll()
		return
	}
	// The old UDP mapping is tied to the previous network. Clear all cached
	// peer observations and per-superpeer sockets before rebuilding transport;
	// otherwise a Wi-Fi -> LTE transition can keep stale symmetric state and
	// never start a scan for the new endpoint.
	n.resetTransportState()
	if err := n.restoreTUNNetwork(); err != nil {
		n.logf("%s: TUN network restore failed: %v", source, err)
	}
	n.c.endpoint = endpoint
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	if err := n.register(); err != nil {
		n.logf("%s: re-register failed: %v", source, err)
		return
	}
	if err := n.bootstrap(); err != nil {
		n.logf("%s: topology refresh failed: %v", source, err)
		return
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.logf("%s: symmetric handshake did not complete", source)
	}
	// After an IP change every peer still points at the dead mapping. HELLO
	// and PING through the new socket let every peer relearn the fresh source
	// address immediately instead of waiting for the next keepalive tick.
	n.helloAll()
	n.pingAll()
}
func endpointIP(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(endpoint))
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSpace(host))
}
func endpointIPChanged(previous, next string) bool {
	return previous == "" || endpointIP(previous) != endpointIP(next)
}
func (n *node) register() error {
	r := map[string]any{"node_id": n.id.ID, "public_key": n.id.Public, "nat_type": n.c.nat, "role": n.requestedRole, "relay_capable": !n.c.noRelay, "endpoint": n.c.endpoint, "capacity": n.c.capacity, "mesh_ip": n.c.meshIP}
	// Piggyback link measurements on the heartbeat so the coordinator keeps
	// fresh RTT/up-state without a separate telemetry request. Coordinators
	// decode with DisallowUnknownFields, so an older one rejects the field;
	// remember that and let the telemetry loop cover metrics instead.
	if !n.linksRejected.Load() {
		r["links"] = n.currentLinks()
	}
	// goarch lets the coordinator target update commands at the right binary
	// build. Same compatibility rule as links: drop the field and retry if an
	// old coordinator rejects it.
	if !n.goarchRejected.Load() {
		r["goarch"] = runtime.GOOS + "/" + runtime.GOARCH
	}
	// lan_addrs lets peers in adjacent subnets of the same physical network
	// (cascaded routers) probe this node with unicast HELLOs; broadcast LAN
	// discovery cannot cross a router. Same compatibility rule as above.
	if !n.lanAddrsRejected.Load() {
		if addrs := n.advertisedLanAddrs(); len(addrs) > 0 {
			r["lan_addrs"] = addrs
		}
	}
	var out struct {
		MeshIP string `json:"mesh_ip"`
		Role   string `json:"assigned_role"`
		Token  string `json:"network_token"`
	}
	if e := n.request("POST", "/v1/register", r, &out); e != nil {
		if strings.Contains(e.Error(), "status 400") {
			// The strict decoder rejected at least one optional field. Drop
			// them one at a time (newest first) and retry.
			if !n.linksRejected.Load() {
				n.linksRejected.Store(true)
				delete(r, "links")
			}
			if !n.goarchRejected.Load() {
				n.goarchRejected.Store(true)
				delete(r, "goarch")
			}
			if !n.lanAddrsRejected.Load() {
				n.lanAddrsRejected.Store(true)
				delete(r, "lan_addrs")
			}
			if e = n.request("POST", "/v1/register", r, &out); e != nil {
				return e
			}
		} else {
			return e
		}
	}
	if out.MeshIP == "" {
		return errors.New("coordinator did not assign mesh_ip")
	}
	meshIP, err := netip.ParseAddr(out.MeshIP)
	if err != nil || !meshIP.Is4() {
		return fmt.Errorf("coordinator assigned invalid mesh IPv4 address %q", out.MeshIP)
	}
	n.meshIPv4.Store(binary.BigEndian.Uint32(meshIP.AsSlice()))
	n.c.meshIP = out.MeshIP
	n.c.role = out.Role
	if out.Token != "" {
		n.c.token = out.Token
		n.c.inviteToken = ""
		k := sha256.Sum256([]byte(out.Token))
		n.key = k[:]
		persisted := n.c
		persisted.role = n.requestedRole
		// n.c.nat contains the result of the latest automatic detection.
		// Persist the user's mode instead, otherwise an auto-detected
		// "symmetric" value becomes a permanent setting after enrollment and
		// future reconnects cannot update it to "cone".
		persisted.nat = n.requestedNAT
		if err := saveInteractiveConfig(persisted); err != nil {
			return fmt.Errorf("persist enrolled network token: %w", err)
		}
		n.logf("invite accepted; permanent network credentials saved")
	}
	// Registration is repeated periodically to refresh the coordinator lease.
	// Keep the normal log useful: report this state once and only when it changes.
	n.mu.Lock()
	changed := n.lastLoggedMeshIP != out.MeshIP || n.lastLoggedRole != out.Role
	if changed {
		n.lastLoggedMeshIP = out.MeshIP
		n.lastLoggedRole = out.Role
	}
	n.mu.Unlock()
	if changed {
		n.logf("mesh IP %s; assigned role %s", out.MeshIP, out.Role)
	}
	// The control plane just proved the network path works. If earlier
	// recovery attempts collected backoff (for example STUN failures while a
	// mobile network was still settling), reset it: the next genuine outage
	// must be handled immediately, not after minutes of exponential delay.
	// TryLock: callers that already hold recoveryMu reset nothing here.
	if n.recoveryMu.TryLock() {
		n.recoveryFails = 0
		n.recoveryNext = time.Time{}
		n.recoveryMu.Unlock()
	}
	return nil
}

func configureUDPSocket(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(udpSocketBufferSize)
	_ = conn.SetWriteBuffer(udpSocketBufferSize)
}

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
