package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"home-udp-mesh/internal/protocol"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"
)

func (s *server) adminNode(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	if id == "" {
		reply(w, 400, map[string]string{"error": "missing node_id"})
		return
	}
	result, err := s.db.Exec("DELETE FROM nodes WHERE node_id=?", id)
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		reply(w, 404, map[string]string{"error": "node not found"})
		return
	}
	_, _ = s.db.Exec("DELETE FROM services WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM role_overrides WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM node_network WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM dns_records WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM node_firewall WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM node_tokens WHERE node_id=?", id)
	// Removal is permanent: ban the persistent identity so the node cannot
	// simply re-register on its next restart. Unban via /v1/admin/revoked.
	_, _ = s.db.Exec("INSERT INTO revoked_nodes(node_id,reason,revoked_at) VALUES(?,'removed via admin panel',?) ON CONFLICT(node_id) DO UPDATE SET reason=excluded.reason,revoked_at=excluded.revoked_at", id, time.Now().Unix())
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_deleted", id)
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_revoked", id)
	s.broadcast("topology", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]string{"status": "deleted"})
}
func (s *server) adminNodeRole(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil || (input.Role != "auto" && input.Role != "iot" && input.Role != "client" && input.Role != "superpeer") {
		reply(w, 400, map[string]string{"error": "role must be auto, iot, client or superpeer"})
		return
	}
	var nat string
	if err := s.db.QueryRow("SELECT nat_type FROM nodes WHERE node_id=?", id).Scan(&nat); err != nil {
		reply(w, 404, map[string]string{"error": "node not found"})
		return
	}
	if input.Role == "superpeer" && nat != "cone" {
		reply(w, 409, map[string]string{"error": "only cone NAT nodes can be superpeers"})
		return
	}
	if _, err := s.db.Exec("INSERT INTO role_overrides(node_id,role) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET role=excluded.role", id, input.Role); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.db.Exec("UPDATE nodes SET requested_role=? WHERE node_id=?", input.Role, id); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if accountID, scoped := s.accountIDForRequest(r); scoped {
		if _, err := s.rebalanceRolesFor(&accountID); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
	} else if _, err := s.rebalanceRoles(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "role_changed", id+":"+input.Role)
	s.broadcast("topology", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]string{"status": "ok", "role": input.Role})
}
func (s *server) allocate() (string, error) {
	rows, e := s.db.Query("SELECT mesh_ip FROM nodes WHERE mesh_ip IS NOT NULL")
	if e != nil {
		return "", e
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var x string
		rows.Scan(&x)
		used[x] = true
	}
	ip := append(net.IP(nil), s.network.IP...)
	for inc(ip); s.network.Contains(ip); inc(ip) {
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("mesh address pool is exhausted")
}
func (s *server) assign(id, requested, nat string, relay bool, capacity int, now int64) (string, error) {
	s.configMu.RLock()
	ttl, auto := s.ttl, s.auto
	s.configMu.RUnlock()
	if requested == "superpeer" {
		return "superpeer", nil
	}
	// "iot" nodes are leaves: never eligible as a relay/rendezvous superpeer.
	if requested == "iot" {
		return "client", nil
	}
	if requested == "client" || nat != "cone" || !relay {
		return "client", nil
	}
	all, e := s.rows("SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes WHERE last_seen>=? AND node_id!=?", now-ttl, id)
	if e != nil {
		return "", e
	}
	manual := 0
	var c []node
	for _, n := range all {
		if n.RequestedRole == "superpeer" {
			manual++
		}
		if n.RequestedRole == "auto" && n.NAT == "cone" && n.Relay {
			c = append(c, n)
		}
	}
	target := auto
	if target == 0 {
		// sqrt grows the backbone slowly while still giving a small network
		// redundancy. Manual superpeers are counted separately below.
		target = intSqrtCeil(len(c))
	}
	slots := target - manual
	if slots <= 0 {
		return "client", nil
	}
	var created int64 = now
	s.db.QueryRow("SELECT created_at FROM nodes WHERE node_id=?", id).Scan(&created)
	c = append(c, node{ID: id, Capacity: capacity, CreatedAt: created})
	sort.Slice(c, func(i, j int) bool {
		if c[i].Capacity != c[j].Capacity {
			return c[i].Capacity > c[j].Capacity
		}
		if c[i].CreatedAt != c[j].CreatedAt {
			return c[i].CreatedAt < c[j].CreatedAt
		}
		return c[i].ID < c[j].ID
	})
	for _, n := range c[:min(slots, len(c))] {
		if n.ID == id {
			return "superpeer", nil
		}
	}
	return "client", nil
}
func (s *server) registeredNode(id string) (*node, sql.NullInt64, sql.NullString, error) {
	var n node
	var relay int
	var owner sql.NullInt64
	var override sql.NullString
	err := s.registerLookupStmt.QueryRow(id).Scan(
		&n.ID, &n.PublicKey, &n.NAT, &n.Role, &n.Endpoint, &n.RequestedRole,
		&relay, &n.Capacity, &n.LastSeen, &n.CreatedAt, &n.ConnectedAt, &n.MeshIP, &n.GoArch, &owner, &override,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, owner, override, nil
	}
	if err != nil {
		return nil, owner, override, err
	}
	n.Relay = relay != 0
	return &n, owner, override, nil
}
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	accountID, accountScoped := s.accountIDForRequest(r)
	if !accountScoped {
		if invite := r.Header.Get("X-Mesh-Invite"); invite != "" {
			var invitedOwner sql.NullInt64
			if s.db.QueryRow("SELECT owner_id FROM invites WHERE token=? AND used_at IS NOT NULL", invite).Scan(&invitedOwner) == nil && invitedOwner.Valid {
				accountID, accountScoped = invitedOwner.Int64, true
			}
		}
	}
	var d struct {
		ID       string                     `json:"node_id"`
		Public   string                     `json:"public_key"`
		NAT      string                     `json:"nat_type"`
		Role     string                     `json:"role"`
		Endpoint string                     `json:"endpoint"`
		MeshIP   string                     `json:"mesh_ip"`
		Capacity int                        `json:"capacity"`
		Relay    *bool                      `json:"relay_capable"`
		Links    []protocol.LinkMeasurement `json:"links"`
		GoArch   string                     `json:"goarch"`
		LANAddrs []string                   `json:"lan_addrs"`
	}
	if decodeJSON(w, r, &d) != nil || d.ID == "" || len(d.ID) > 128 || d.Public == "" || len(d.Public) > 256 || d.Endpoint == "" || len(d.Endpoint) > 256 || !(d.NAT == "cone" || d.NAT == "symmetric") || !(d.Role == "auto" || d.Role == "iot" || d.Role == "client" || d.Role == "superpeer") {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
		return
	}
	if !validGoArch(d.GoArch) {
		reply(w, 400, map[string]any{"error": "invalid goarch"})
		return
	}
	if _, _, err := net.SplitHostPort(d.Endpoint); err != nil {
		reply(w, 400, map[string]any{"error": "invalid endpoint"})
		return
	}
	pub, e := protocol.B64Decode(d.Public)
	if e != nil || protocol.NodeID(pub) != d.ID {
		reply(w, 400, map[string]any{"error": "node_id does not match public_key"})
		return
	}
	// A banned identity stays banned no matter which credential it presents:
	// this is what makes removing a node from the mesh permanent.
	if s.nodeRevoked(d.ID) {
		reply(w, http.StatusForbidden, map[string]any{"error": "node revoked by coordinator"})
		return
	}
	previous, existingOwner, roleOverride, e := s.registeredNode(d.ID)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	if accountScoped && existingOwner.Valid && existingOwner.Int64 != accountID {
		reply(w, http.StatusForbidden, map[string]any{"error": "node belongs to another account"})
		return
	}
	if roleOverride.Valid {
		d.Role = roleOverride.String
	}
	if d.Role == "superpeer" && d.NAT != "cone" {
		reply(w, 400, map[string]any{"error": "only cone nodes may be superpeers"})
		return
	}
	if d.MeshIP != "" && net.ParseIP(d.MeshIP).To4() == nil {
		reply(w, 400, map[string]any{"error": "invalid mesh_ip"})
		return
	}
	relay := true
	if d.Relay != nil {
		relay = *d.Relay
	}
	if d.Capacity < 1 {
		d.Capacity = 1
	}
	if d.Capacity > 1000 {
		d.Capacity = 1000
	}
	now := time.Now().Unix()
	// Allocation, stale-lease reclamation and the insert are a check-then-act
	// sequence. Two concurrent first registrations could otherwise both pass
	// the free-address check and receive the same mesh IP.
	s.registerMu.Lock()
	ip := d.MeshIP
	if ip == "" && previous != nil {
		ip = previous.MeshIP
	}
	if ip == "" {
		ip, e = s.allocate()
		if e != nil {
			s.registerMu.Unlock()
			reply(w, 500, map[string]any{"error": e.Error()})
			return
		}
	}
	ttl := s.settings().TTL
	if previous == nil || ip != previous.MeshIP {
		var owner string
		var ownerLastSeen int64
		s.db.QueryRow("SELECT node_id,last_seen FROM nodes WHERE mesh_ip=? AND node_id!=?", ip, d.ID).Scan(&owner, &ownerLastSeen)
		if owner != "" {
			if ownerLastSeen >= now-int64(ttl) {
				s.registerMu.Unlock()
				reply(w, 409, map[string]any{"error": "mesh_ip is already assigned"})
				return
			}
			// A crashed or replaced client may leave its last mesh address in the
			// registry. It is safe to reclaim it once the previous registration is
			// outside the online TTL; keep the old device row for offline inventory.
			if _, e = s.db.Exec("UPDATE nodes SET mesh_ip='' WHERE node_id=?", owner); e != nil {
				s.registerMu.Unlock()
				reply(w, 500, map[string]any{"error": e.Error()})
				return
			}
		}
	}
	// Existing nodes retain their role until the authoritative rebalance below.
	// Re-running assign on every 15-second heartbeat duplicated the full online
	// node scan and sort performed by rebalanceRolesFor.
	role := "client"
	if previous != nil {
		role = previous.Role
	} else if d.Role == "superpeer" {
		// The authoritative rebalance immediately below picks auto candidates.
		// Preserve a manually requested superpeer until that pass runs.
		role = "superpeer"
	}
	var ownerValue any
	if accountScoped {
		ownerValue = accountID
	}
	lanAddrs := sanitizeLanAddrs(d.LANAddrs)
	lanAddrsJSON, _ := json.Marshal(lanAddrs)
	if previous == nil {
		_, e = s.registerInsertStmt.Exec(d.ID, d.Public, d.NAT, role, d.Endpoint, d.Role, boolInt(relay), d.Capacity, now, now, now, ip, d.GoArch, string(lanAddrsJSON), ownerValue)
	} else {
		_, e = s.registerUpdateStmt.Exec(d.Public, d.NAT, role, d.Endpoint, d.Role, boolInt(relay), d.Capacity, now, now-int64(ttl), now, ip, d.GoArch, string(lanAddrsJSON), ownerValue, d.ID)
	}
	s.registerMu.Unlock()
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	// Newer nodes fold their link measurements into the heartbeat so the
	// coordinator keeps fresh RTT/up-state without a separate telemetry
	// request every few seconds. Optional: older clients omit links and keep
	// using /v1/telemetry.
	if len(d.Links) > 0 && s.updateLinkMetrics(d.ID, d.Links) {
		s.metricStamp.Add(1)
	}
	s.broadcast("topology")
	// Invite-based enrollment used to hand out the account's admin-grade API
	// token, so a six-character setup key was enough to obtain a permanent
	// full-privilege credential. Nodes now receive a credential bound to their
	// own identity: it only satisfies node-facing endpoints (bootstrap,
	// telemetry, services, the control websocket) and dies with the node. The
	// legacy "network_token" field name is kept for wire compatibility, and
	// every invite enrollment gets one — the owner-less path previously left
	// the node without any permanent credential at all.
	var enrollmentToken string
	if r.Header.Get("X-Mesh-Invite") != "" {
		enrollmentToken, e = s.issueNodeToken(d.ID)
		if e != nil {
			reply(w, http.StatusInternalServerError, map[string]any{"error": "could not issue node token"})
			return
		}
	}
	// A normal heartbeat changes only last_seen. Do not scan and sort every
	// online node in rebalanceRolesFor unless eligibility or ownership changed.
	needsRebalance := previous == nil || previous.LastSeen < now-int64(ttl) ||
		(previous != nil && (previous.NAT != d.NAT || previous.RequestedRole != d.Role || previous.Relay != relay || previous.Capacity != d.Capacity)) ||
		(accountScoped && !existingOwner.Valid)
	if needsRebalance {
		var rebalanced bool
		if accountScoped {
			rebalanced, e = s.rebalanceRolesFor(&accountID)
		} else {
			rebalanced, e = s.rebalanceRoles()
		}
		if e != nil {
			reply(w, 500, map[string]any{"error": e.Error()})
			return
		}
		if rebalanced {
			// A promotion or demotion moves edges between other nodes too;
			// drop the cached graph so the next bootstrap serves fresh links.
			s.invalidateLinkCache()
		}
		_ = s.db.QueryRow("SELECT role FROM nodes WHERE node_id=?", d.ID).Scan(&role)
	}
	topologyChanged := registrationChangesTopology(previous, now-int64(ttl), node{
		PublicKey: d.Public, NAT: d.NAT, Role: role, Endpoint: d.Endpoint,
		RequestedRole: d.Role, Relay: relay, Capacity: d.Capacity, MeshIP: ip,
	})
	if topologyChanged {
		log.Printf("[SERVER] register node=%s role=%s mesh_ip=%s", d.ID[:8], role, ip)
	}
	response := map[string]any{"status": "ok", "mesh_ip": ip, "mesh_network": s.network.String(), "assigned_role": role, "topology_changed": topologyChanged}
	if enrollmentToken != "" {
		response["network_token"] = enrollmentToken
	}
	reply(w, 200, response)
}
func registrationChangesTopology(previous *node, onlineAfter int64, next node) bool {
	if previous == nil || previous.LastSeen < onlineAfter {
		return true
	}
	return previous.PublicKey != next.PublicKey ||
		previous.NAT != next.NAT ||
		previous.Role != next.Role ||
		previous.Endpoint != next.Endpoint ||
		previous.RequestedRole != next.RequestedRole ||
		previous.Relay != next.Relay ||
		previous.Capacity != next.Capacity ||
		previous.MeshIP != next.MeshIP
}
func (s *server) rendezvousRegister(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Session  string `json:"session"`
		ID       string `json:"id"`
		External string `json:"external"`
		NATType  string `json:"nat_type"`
	}
	if decodeJSON(w, r, &request) != nil || len(request.Session) == 0 || len(request.Session) > 128 || len(request.ID) == 0 || len(request.ID) > 128 || request.External == "" || len(request.External) > 256 || (request.NATType != "cone" && request.NATType != "symmetric") {
		reply(w, http.StatusBadRequest, map[string]any{"error": "missing or invalid fields"})
		return
	}
	if _, _, err := net.SplitHostPort(request.External); err != nil {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid external endpoint"})
		return
	}

	s.sessionsMu.Lock()
	// Prune expired sessions so unauthenticated legacy clients cannot grow the
	// heap without limit. Waiters hold their own HTTP timeouts, so dropping a
	// session only ends matching for long-dead peers.
	now := time.Now()
	for id, peers := range s.sessions {
		fresh := false
		for _, peer := range peers {
			if now.Sub(peer.created) < rendezvousSessionTTL {
				fresh = true
				break
			}
		}
		if !fresh {
			delete(s.sessions, id)
		}
	}
	peers := s.sessions[request.Session]
	if peers == nil {
		if len(s.sessions) >= rendezvousMaxSessions {
			s.sessionsMu.Unlock()
			reply(w, http.StatusTooManyRequests, map[string]any{"error": "rendezvous capacity reached; retry later"})
			return
		}
		peers = map[string]*rendezvousPeer{}
		s.sessions[request.Session] = peers
	}
	peers[request.ID] = &rendezvousPeer{endpoint: request.External, natType: request.NATType, status: "waiting", ready: make(chan struct{}), created: now}
	if len(peers) == 2 {
		ids := make([]string, 0, 2)
		for id := range peers {
			ids = append(ids, id)
		}
		first, second := peers[ids[0]], peers[ids[1]]
		if first.natType == "symmetric" && second.natType == "symmetric" {
			for _, peer := range peers {
				peer.status = "incompatible"
				close(peer.ready)
			}
		} else {
			first.status, first.other, first.otherNAT = "ready", second.endpoint, second.natType
			second.status, second.other, second.otherNAT = "ready", first.endpoint, first.natType
			close(first.ready)
			close(second.ready)
		}
	}
	s.sessionsMu.Unlock()
	log.Printf("[SERVER] rendezvous register session=%s peer=%s nat=%s", request.Session, request.ID, request.NATType)
	reply(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *server) rendezvousWait(w http.ResponseWriter, r *http.Request) {
	session, id := r.URL.Query().Get("session"), r.URL.Query().Get("id")
	timeout, err := strconv.Atoi(r.URL.Query().Get("timeout"))
	if err != nil || timeout <= 0 {
		timeout = 30
	}
	timeout = min(timeout, 120)
	// The server-wide WriteTimeout counts from the start of the request. A
	// peer that registers 40 seconds into this poll would otherwise never
	// receive the ready response, so extend the deadline for this wait only.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(timeout)*time.Second + 10*time.Second))
	s.sessionsMu.Lock()
	peer := s.sessions[session][id]
	s.sessionsMu.Unlock()
	if peer == nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "not registered"})
		return
	}
	select {
	case <-peer.ready:
	case <-time.After(time.Duration(timeout) * time.Second):
		reply(w, http.StatusRequestTimeout, map[string]string{"status": "timeout"})
		return
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if peer.status == "incompatible" {
		reply(w, http.StatusConflict, map[string]string{"status": "incompatible", "error": "symmetric-symmetric is unsupported"})
		return
	}
	if peer.status != "ready" {
		reply(w, http.StatusRequestTimeout, map[string]string{"status": "timeout"})
		return
	}
	reply(w, http.StatusOK, map[string]string{"status": "ready", "peer": peer.other, "peer_nat_type": peer.otherNAT})
}
func (s *server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	ttl := s.settings().TTL
	accountID, scoped := s.accountIDForRequest(r)
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes WHERE last_seen>=?"
	args := []any{time.Now().Unix() - int64(ttl)}
	if scoped {
		query += " AND owner_id=?"
		args = append(args, accountID)
	}
	query += " ORDER BY node_id"
	all, e := s.rows(query, args...)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	s.enrichNodes(all)
	var self *node
	for i := range all {
		if all[i].ID == id {
			self = &all[i]
		}
	}
	if self == nil {
		reply(w, 404, map[string]any{"error": "unknown node"})
		return
	}
	ls := s.cachedTopologyLinks(all)
	neighbors := map[string]bool{}
	for _, l := range ls {
		if l.A == id {
			neighbors[l.B] = true
		}
		if l.B == id {
			neighbors[l.A] = true
		}
	}
	var peers []node
	for _, n := range all {
		if neighbors[n.ID] {
			peers = append(peers, n)
		}
	}
	serviceQuery := "SELECT services.node_id,services.name FROM services JOIN nodes ON nodes.node_id=services.node_id"
	serviceArgs := []any{}
	if scoped {
		serviceQuery += " WHERE nodes.owner_id=?"
		serviceArgs = append(serviceArgs, accountID)
	}
	serviceQuery += " ORDER BY services.node_id,services.name"
	rs, e := s.db.Query(serviceQuery, serviceArgs...)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	var services []map[string]string
	for rs.Next() {
		var n, x string
		rs.Scan(&n, &x)
		services = append(services, map[string]string{"node_id": n, "name": x})
	}
	rs.Close()
	forwards := []portForward{}
	rows, err := s.db.Query(`SELECT id,source_node_id,listen_host,listen_port,target_node_id,target_host,target_port FROM port_forwards WHERE source_node_id=? OR target_node_id=? ORDER BY id`, id, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var f portForward
			if rows.Scan(&f.ID, &f.Source, &f.ListenHost, &f.ListenPort, &f.Target, &f.TargetHost, &f.TargetPort) == nil {
				forwards = append(forwards, f)
			}
		}
	}
	settings := s.settings()
	version := bootstrapTopologyVersion(all, ls)
	version += "-dns" + fmt.Sprintf("%x", sha256.Sum256([]byte(settings.DNSUpstream)))[:12]
	encoded, _ := json.Marshal(forwards)
	version += "-f" + fmt.Sprintf("%x", sha256.Sum256(encoded))[:12]
	encoded, _ = json.Marshal(services)
	version += "-s" + fmt.Sprintf("%x", sha256.Sum256(encoded))[:12]
	firewall := s.loadFirewall(id)
	encoded, _ = json.Marshal(firewall)
	version += "-fw" + fmt.Sprintf("%x", sha256.Sum256(encoded))[:12]
	if bootstrapUnchanged(w, r, version) {
		return
	}
	reply(w, 200, map[string]any{"topology_version": version, "self": self, "neighbors": peers, "directory": all, "backbone_links": ls, "dns_upstream": settings.DNSUpstream, "services": services, "forwards": forwards, "firewall": firewall, "graph_update_mode": "reserved"})
}
