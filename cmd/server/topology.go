package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"home-udp-mesh/internal/protocol"

	_ "modernc.org/sqlite"
)

func (s *server) rebalanceRoles() (bool, error) {
	return s.rebalanceRolesFor(nil)
}

func (s *server) rebalanceRolesFor(ownerID *int64) (bool, error) {
	c := s.settings()
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes WHERE last_seen>=?"
	args := []any{time.Now().Unix() - int64(c.TTL)}
	if ownerID != nil {
		query += " AND owner_id=?"
		args = append(args, *ownerID)
	}
	nodes, err := s.rows(query, args...)
	if err != nil {
		return false, err
	}
	manual, candidates := 0, make([]node, 0, len(nodes))
	for _, n := range nodes {
		if n.RequestedRole == "superpeer" {
			manual++
			continue
		}
		if n.RequestedRole == "auto" && n.NAT == "cone" && n.Relay {
			candidates = append(candidates, n)
		}
	}
	target := c.AutoSuperpeers
	if target == 0 {
		target = intSqrtCeil(len(candidates))
	}
	target = max(0, target-manual)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Capacity != candidates[j].Capacity {
			return candidates[i].Capacity > candidates[j].Capacity
		}
		if candidates[i].CreatedAt != candidates[j].CreatedAt {
			return candidates[i].CreatedAt < candidates[j].CreatedAt
		}
		return candidates[i].ID < candidates[j].ID
	})
	super := map[string]bool{}
	for _, n := range nodes {
		if n.RequestedRole == "superpeer" {
			super[n.ID] = true
		}
	}
	for _, n := range candidates[:min(target, len(candidates))] {
		super[n.ID] = true
	}
	changed := false
	for _, n := range nodes {
		role := "client"
		if super[n.ID] {
			role = "superpeer"
		}
		if n.Role == role {
			continue
		}
		if _, err := s.db.Exec("UPDATE nodes SET role=? WHERE node_id=?", role, n.ID); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// adminTopology returns the authenticated account’s view of its mesh.
func (s *server) adminTopology(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ttl := s.settings().TTL
	now := time.Now().Unix()
	scope := r.URL.Query().Get("scope")
	all := scope == "all"
	accountID, scoped := s.accountIDForRequest(r)
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes WHERE last_seen>=?"
	args := []any{now - int64(ttl)}
	if all {
		query = "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes"
		args = nil
	}
	if scoped {
		query += " WHERE owner_id=?"
		args = append(args, accountID)
		if !all {
			query = strings.Replace(query, " WHERE last_seen>=? WHERE owner_id=?", " WHERE last_seen>=? AND owner_id=?", 1)
		}
	}
	query += " ORDER BY node_id"
	nodes, err := s.rows(query, args...)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.enrichNodes(nodes)
	for i := range nodes {
		// Uptime is measured from the beginning of the current online session,
		// not from persistent node creation or the latest heartbeat.
		nodes[i].UptimeSeconds = now - nodes[i].ConnectedAt
		if nodes[i].UptimeSeconds < 0 {
			nodes[i].UptimeSeconds = 0
		}
		nodes[i].Online = nodes[i].LastSeen >= now-int64(ttl)
	}
	links := s.links(nodes)
	if all {
		// Keep the live topology based on online nodes, but expose stored manual
		// links to offline nodes so they can still be edited in the graph.
		online := make([]node, 0, len(nodes))
		for _, n := range nodes {
			if n.Online {
				online = append(online, n)
			}
		}
		links = s.links(online)
		seen := map[string]bool{}
		for _, e := range links {
			seen[edgeKey(e.A, e.B)] = true
		}
		missing := []link{}
		for _, e := range s.manualLinksForNodes(nodes) {
			if !seen[edgeKey(e.A, e.B)] {
				missing = append(missing, e)
			}
		}
		links = append(links, s.decorateLinks(missing, nodes)...)
	}
	reply(w, http.StatusOK, map[string]any{"scope": map[bool]string{true: "all", false: "online"}[all], "nodes": nodes, "links": links, "settings": s.settings()})
}

func (s *server) enrichNodes(nodes []node) {
	rows, err := s.db.Query("SELECT node_id,name,routes,dns_ip FROM node_network")
	if err != nil {
		return
	}
	byID := map[string]*node{}
	for i := range nodes {
		byID[nodes[i].ID] = &nodes[i]
	}
	for rows.Next() {
		var id, name, raw, legacyDNS string
		if rows.Scan(&id, &name, &raw, &legacyDNS) != nil {
			continue
		}
		if n := byID[id]; n != nil {
			n.Name, n.Routes = name, parseRouteAds(raw)
		}
	}
	rows.Close()
	records, err := s.db.Query("SELECT node_id,name,lan_ip FROM dns_records ORDER BY name")
	if err != nil {
		return
	}
	defer records.Close()
	for records.Next() {
		var id string
		var record dnsRecord
		if records.Scan(&id, &record.Name, &record.IP) != nil {
			continue
		}
		if n := byID[id]; n != nil {
			record.VirtualIP = translatedIP(record.IP, n.Routes, true)
			n.DNSRecords = append(n.DNSRecords, record)
		}
	}
}

func parseRouteAds(raw string) []routeAdvertisement {
	var routes []routeAdvertisement
	if json.Unmarshal([]byte(raw), &routes) == nil && routes != nil {
		return routes
	}
	var legacy []string
	if json.Unmarshal([]byte(raw), &legacy) == nil {
		for _, lan := range legacy {
			routes = append(routes, routeAdvertisement{LAN: lan})
		}
	}
	return routes
}

func translatedIP(raw string, routes []routeAdvertisement, toVirtual bool) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	for _, r := range routes {
		lan, e1 := netip.ParsePrefix(r.LAN)
		virtual, e2 := netip.ParsePrefix(r.Virtual)
		if e1 != nil || e2 != nil {
			continue
		}
		from, to := lan, virtual
		if !toVirtual {
			from, to = virtual, lan
		}
		if from.Contains(ip) {
			a := ip.As4()
			b := from.Addr().As4()
			c := to.Addr().As4()
			offset := binary.BigEndian.Uint32(a[:]) - binary.BigEndian.Uint32(b[:])
			v := binary.BigEndian.Uint32(c[:]) + offset
			var out [4]byte
			binary.BigEndian.PutUint32(out[:], v)
			return netip.AddrFrom4(out).String()
		}
	}
	return ""
}

func validDNSName(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func (s *server) adminNodeNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var d struct {
		Name       string      `json:"name"`
		Routes     []string    `json:"routes"`
		DNSRecords []dnsRecord `json:"dns_records"`
	}
	if decodeJSON(w, r, &d) != nil {
		reply(w, 400, map[string]string{"error": "invalid network settings"})
		return
	}
	d.Name = strings.ToLower(strings.TrimSpace(d.Name))
	if !validDNSName(d.Name) {
		reply(w, 400, map[string]string{"error": "name must contain only lowercase letters, digits and hyphens"})
		return
	}
	seen := map[string]bool{}
	for i, raw := range d.Routes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !p.Addr().Is4() {
			reply(w, 400, map[string]string{"error": "routes must be IPv4 CIDRs"})
			return
		}
		p = p.Masked()
		if p.Bits() < 16 || p.Bits() > 30 {
			reply(w, 400, map[string]string{"error": "LAN routes must have prefixes between /16 and /30"})
			return
		}
		d.Routes[i] = p.String()
		if seen[d.Routes[i]] {
			reply(w, 400, map[string]string{"error": "duplicate route"})
			return
		}
		seen[d.Routes[i]] = true
	}
	rows, err := s.db.Query("SELECT node_id,routes FROM node_network")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	used := []netip.Prefix{}
	old := map[string]string{}
	for rows.Next() {
		var other, raw string
		_ = rows.Scan(&other, &raw)
		for _, route := range parseRouteAds(raw) {
			if other == id {
				old[route.LAN] = route.Virtual
			} else if p, e := netip.ParsePrefix(route.Virtual); e == nil {
				used = append(used, p)
			}
		}
	}
	rows.Close()
	meshPrefix, _ := netip.ParsePrefix(s.network.String())
	used = append(used, meshPrefix)
	allocated := make([]routeAdvertisement, 0, len(d.Routes))
	for _, lan := range d.Routes {
		bits := mustPrefix(lan).Bits()
		virtual := old[lan]
		if p, e := netip.ParsePrefix(virtual); e != nil || prefixOverlapsAny(p, used) {
			virtual = ""
		}
		if virtual == "" {
			virtual = allocateVirtual(bits, used)
			if virtual == "" {
				reply(w, 409, map[string]string{"error": "10.77.0.0/16 virtual address pool is exhausted"})
				return
			}
		}
		p, _ := netip.ParsePrefix(virtual)
		used = append(used, p)
		allocated = append(allocated, routeAdvertisement{LAN: lan, Virtual: virtual})
	}
	var exists int
	if s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", id).Scan(&exists) != nil {
		reply(w, 404, map[string]string{"error": "unknown node"})
		return
	}
	if d.Name != "" {
		var owner string
		_ = s.db.QueryRow("SELECT node_id FROM node_network WHERE name=? AND node_id!=?", d.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "name already used"})
			return
		}
		_ = s.db.QueryRow("SELECT node_id FROM dns_records WHERE name=? AND node_id!=?", d.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "name already used by a LAN object"})
			return
		}
	}
	names := map[string]bool{}
	for i := range d.DNSRecords {
		r := &d.DNSRecords[i]
		r.Name = strings.ToLower(strings.TrimSpace(r.Name))
		r.IP = strings.TrimSpace(r.IP)
		if !validDNSName(r.Name) || r.Name == "" || names[r.Name] || r.Name == d.Name {
			reply(w, 400, map[string]string{"error": "invalid or duplicate DNS object name"})
			return
		}
		names[r.Name] = true
		if translatedIP(r.IP, allocated, true) == "" {
			reply(w, 400, map[string]string{"error": fmt.Sprintf("DNS object %s is outside advertised LAN routes", r.Name)})
			return
		}
		r.VirtualIP = translatedIP(r.IP, allocated, true)
		var owner string
		_ = s.db.QueryRow("SELECT node_id FROM dns_records WHERE name=? AND node_id!=?", r.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "DNS name already used"})
			return
		}
		_ = s.db.QueryRow("SELECT node_id FROM node_network WHERE name=?", r.Name).Scan(&owner)
		if owner != "" && owner != id {
			reply(w, 409, map[string]string{"error": "DNS name already used"})
			return
		}
	}
	raw, _ := json.Marshal(allocated)
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO node_network(node_id,name,routes,dns_ip) VALUES(?,?,?,'') ON CONFLICT(node_id) DO UPDATE SET name=excluded.name,routes=excluded.routes,dns_ip=''", id, d.Name, string(raw)); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = tx.Exec("DELETE FROM dns_records WHERE node_id=?", id)
	for _, record := range d.DNSRecords {
		if _, err = tx.Exec("INSERT INTO dns_records(node_id,name,lan_ip) VALUES(?,?,?)", id, record.Name, record.IP); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
			return
		}
	}
	_, _ = tx.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_network", fmt.Sprintf("node=%s name=%s routes=%s", id, d.Name, string(raw)))
	s.broadcast("topology", "audit")
	if err = tx.Commit(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.pushTopologies()
	reply(w, 200, map[string]any{"name": d.Name, "routes": allocated, "dns_records": d.DNSRecords})
}

type routeChange struct {
	Route string `json:"route"`
}

func parseLANRoute(raw string) (string, netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !p.Addr().Is4() {
		return "", netip.Prefix{}, errors.New("route must be an IPv4 CIDR")
	}
	p = p.Masked()
	if p.Bits() < 16 || p.Bits() > 30 {
		return "", netip.Prefix{}, errors.New("LAN route prefix must be between /16 and /30")
	}
	return p.String(), p, nil
}

func (s *server) adminAddNodeRoute(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var change routeChange
	if err := decodeJSON(w, r, &change); err != nil {
		reply(w, 400, map[string]string{"error": "invalid route request"})
		return
	}
	lan, prefix, err := parseLANRoute(change.Route)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var exists int
	if s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", id).Scan(&exists) != nil {
		reply(w, 404, map[string]string{"error": "unknown node"})
		return
	}
	var name, raw string
	_ = s.db.QueryRow("SELECT name,routes FROM node_network WHERE node_id=?", id).Scan(&name, &raw)
	routes := parseRouteAds(raw)
	for _, route := range routes {
		if route.LAN == lan {
			reply(w, 409, map[string]string{"error": "route already advertised"})
			return
		}
	}
	rows, err := s.db.Query("SELECT node_id,routes FROM node_network")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	used := []netip.Prefix{}
	for rows.Next() {
		var owner, encoded string
		if rows.Scan(&owner, &encoded) == nil {
			for _, route := range parseRouteAds(encoded) {
				if virtual, e := netip.ParsePrefix(route.Virtual); e == nil {
					used = append(used, virtual)
				}
			}
		}
	}
	rows.Close()
	if mesh, e := netip.ParsePrefix(s.network.String()); e == nil {
		used = append(used, mesh)
	}
	virtual := allocateVirtual(prefix.Bits(), used)
	if virtual == "" {
		reply(w, 409, map[string]string{"error": "10.77.0.0/16 virtual address pool is exhausted"})
		return
	}
	routes = append(routes, routeAdvertisement{LAN: lan, Virtual: virtual})
	encoded, _ := json.Marshal(routes)
	_, err = s.db.Exec("INSERT INTO node_network(node_id,name,routes,dns_ip) VALUES(?,?,?,'') ON CONFLICT(node_id) DO UPDATE SET routes=excluded.routes", id, name, string(encoded))
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_route_added", fmt.Sprintf("node=%s route=%s virtual=%s", id, lan, virtual))
	s.broadcast("topology", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]any{"route": routeAdvertisement{LAN: lan, Virtual: virtual}})
}

func (s *server) adminRemoveNodeRoute(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var change routeChange
	if err := decodeJSON(w, r, &change); err != nil {
		reply(w, 400, map[string]string{"error": "invalid route request"})
		return
	}
	lan, _, err := parseLANRoute(change.Route)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var name, raw string
	if err := s.db.QueryRow("SELECT name,routes FROM node_network WHERE node_id=?", id).Scan(&name, &raw); err != nil {
		reply(w, 404, map[string]string{"error": "node has no advertised routes"})
		return
	}
	old := parseRouteAds(raw)
	remaining := make([]routeAdvertisement, 0, len(old))
	found := false
	for _, route := range old {
		if route.LAN == lan {
			found = true
			continue
		}
		remaining = append(remaining, route)
	}
	if !found {
		reply(w, 404, map[string]string{"error": "route is not advertised"})
		return
	}
	encoded, _ := json.Marshal(remaining)
	if _, err = s.db.Exec("UPDATE node_network SET routes=?,dns_ip='' WHERE node_id=?", string(encoded), id); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// DNS objects whose physical address belonged to the revoked LAN are no
	// longer valid and must not remain advertised with a stale virtual IP.
	rows, _ := s.db.Query("SELECT name,lan_ip FROM dns_records WHERE node_id=?", id)
	if rows != nil {
		for rows.Next() {
			var dnsName, lanIP string
			if rows.Scan(&dnsName, &lanIP) == nil && translatedIP(lanIP, remaining, true) == "" {
				_, _ = s.db.Exec("DELETE FROM dns_records WHERE node_id=? AND name=?", id, dnsName)
			}
		}
		rows.Close()
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_route_removed", fmt.Sprintf("node=%s route=%s", id, lan))
	s.broadcast("topology", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]any{"removed": lan, "routes": remaining})
}

func mustPrefix(raw string) netip.Prefix { p, _ := netip.ParsePrefix(raw); return p }
func prefixOverlapsAny(p netip.Prefix, used []netip.Prefix) bool {
	for _, u := range used {
		if p.Overlaps(u) {
			return true
		}
	}
	return false
}
func allocateVirtual(bits int, used []netip.Prefix) string {
	pool, _ := netip.ParsePrefix("10.77.0.0/16")
	step := uint32(1) << uint(32-bits)
	base := binary.BigEndian.Uint32(pool.Addr().AsSlice())
	for value := base; value+step-1 <= base+65535; value += step {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		p := netip.PrefixFrom(netip.AddrFrom4(raw), bits)
		if !prefixOverlapsAny(p, used) {
			return p.String()
		}
	}
	return ""
}

func metricKey(from, to string) string { return from + "\x00" + to }

// telemetry records link health reported by registered nodes.
func (s *server) telemetry(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var report struct {
		NodeID string                     `json:"node_id"`
		Links  []protocol.LinkMeasurement `json:"links"`
	}
	if err := decodeJSON(w, r, &report); err != nil || report.NodeID == "" {
		reply(w, 400, map[string]string{"error": "invalid telemetry"})
		return
	}
	if !s.requireNodeAccess(w, r, report.NodeID) {
		return
	}
	if s.updateLinkMetrics(report.NodeID, report.Links) {
		s.metricStamp.Add(1)
		s.broadcast("topology")
	}
	reply(w, 200, map[string]string{"status": "ok"})
}

// updateLinkMetrics folds link observations into the shared metrics table and
// reports whether the cached topology graph must be invalidated. Only real
// up/down transitions or first sightings change link costs; pure RTT reports
// arrive every few seconds and must not thrash the shared link cache.
func (s *server) updateLinkMetrics(nodeID string, links []protocol.LinkMeasurement) bool {
	now := time.Now()
	stateChanged := false
	s.metricsMu.Lock()
	for _, x := range links {
		if x.PeerID == "" || x.PeerID == nodeID {
			continue
		}
		k := metricKey(nodeID, x.PeerID)
		old := s.metrics[k]
		if x.RTTMS > 0 && x.RTTMS < 60000 {
			if old.RTTMS == 0 {
				old.RTTMS = x.RTTMS
			} else {
				old.RTTMS = old.RTTMS*.7 + x.RTTMS*.3
			}
		}
		// Loss is already smoothed on the node, so fold it faster (0.5/0.5).
		// Zero reports still decay the estimate toward no-loss. Only a shift
		// across a lossCostStep band invalidates the topology cache: jitter
		// inside a band must not rebuild the graph.
		previousBand := int(old.LossRate / lossCostStep)
		if x.Loss > 0 {
			if old.LossRate == 0 {
				old.LossRate = x.Loss
			} else {
				old.LossRate = old.LossRate*.5 + x.Loss*.5
			}
		} else if old.LossRate > 0 {
			old.LossRate *= 0.5
		}
		if int(old.LossRate/lossCostStep) != previousBand {
			stateChanged = true
		}
		if old.Seen.IsZero() || old.Up != x.Up || old.ViaLAN != x.ViaLAN {
			stateChanged = true
		}
		old.Up = x.Up
		old.ViaLAN = x.ViaLAN
		old.Seen = now
		s.metrics[k] = old
	}
	s.metricsMu.Unlock()
	return stateChanged
}

// Admin push channel (server-sent events). Browsers open GET /v1/admin/stream
// and receive a coalesced "update" event whenever topology, configuration,
// updates or the audit trail change, so the UI reacts immediately instead of
// waiting for the next poll. The 10-second polling cycle stays in place as a
// fallback; SSE only removes the visibility lag. EventSource cannot send the
// X-Mesh-Token header, so the stream authenticates with the account session
// cookie; token-only sessions simply keep polling.
// Broadcasts are coalesced: heartbeats from many nodes within one second
// produce a single event per browser.
func (s *server) broadcast(topics ...string) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	if s.sseClients == nil {
		return
	}
	dirty := false
	for _, t := range topics {
		if !s.sseDirty[t] {
			s.sseDirty[t] = true
			dirty = true
		}
	}
	if dirty && s.sseTimer == nil {
		s.sseTimer = time.AfterFunc(time.Second, s.flushBroadcasts)
	}
}

func (s *server) flushBroadcasts() {
	s.sseMu.Lock()
	topics := make([]string, 0, len(s.sseDirty))
	for t := range s.sseDirty {
		topics = append(topics, t)
	}
	s.sseDirty = map[string]bool{}
	s.sseTimer = nil
	clients := make([]chan []byte, 0, len(s.sseClients))
	for c := range s.sseClients {
		clients = append(clients, c)
	}
	s.sseMu.Unlock()
	if len(topics) == 0 || len(clients) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]any{"topics": topics})
	frame := []byte("event: update\ndata: " + string(payload) + "\n\n")
	for _, c := range clients {
		select {
		case c <- frame:
		default: // slow client: drop the frame, the polling fallback covers it
		}
	}
}

func (s *server) adminStream(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := make(chan []byte, 8)
	s.sseMu.Lock()
	if s.sseClients == nil {
		s.sseClients = map[chan []byte]struct{}{}
		s.sseDirty = map[string]bool{}
	}
	s.sseClients[ch] = struct{}{}
	s.sseMu.Unlock()
	defer func() {
		s.sseMu.Lock()
		delete(s.sseClients, ch)
		s.sseMu.Unlock()
	}()
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()
	// Comment frames keep intermediate proxies from closing an idle stream.
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame := <-ch:
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *server) adminAudit(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if _, scoped := s.accountIDForRequest(r); scoped {
		// Legacy audit rows predate account ownership. Returning them to an
		// account would disclose other tenants' node IDs and operations.
		reply(w, http.StatusOK, []map[string]any{})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	query := "SELECT created_at,event,detail FROM audit_log"
	args := []any{}
	if v := r.URL.Query().Get("before"); v != "" {
		// Cursor pagination: return the page immediately older than the last
		// row the UI already has.
		if ts, e := strconv.ParseInt(v, 10, 64); e == nil && ts > 0 {
			query += " WHERE created_at < ?"
			args = append(args, ts)
		}
	}
	// One extra row distinguishes "page ends here" from "older rows exist"
	// without a separate COUNT query.
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit+1)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	hasMore := false
	for rows.Next() {
		if len(out) == limit {
			hasMore = true
			break
		}
		var at int64
		var event, detail string
		if rows.Scan(&at, &event, &detail) == nil {
			out = append(out, map[string]any{"created_at": at, "event": event, "detail": detail})
		}
	}
	reply(w, 200, map[string]any{"events": out, "has_more": hasMore})
}

// Cost-model references for measured links. RTT doubles the base cost at
// rttCostReferenceMS; the caps keep one pathological measurement (a stalled
// probe, a nearly dead link) from pushing an edge out of the graph entirely,
// keeping it comparable to the down-state penalty instead.
const (
	rttCostReferenceMS = 100.0
	maxRTTCostFactor   = 6.0
	maxLossCostFactor  = 5.0
	lanCostFactor      = 0.5
	// A sustained loss shift that crosses a band boundary changes ranking;
	// jitter inside a band must not rebuild the topology.
	lossCostStep = 0.15
)

func (s *server) decorateLinks(links []link, nodes ...[]node) []link {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	now := time.Now()
	uptime := map[string]int64{}
	if len(nodes) > 0 {
		for _, n := range nodes[0] {
			// Registration is also the node heartbeat, so the current session
			// starts at the most recent registration.
			uptime[n.ID] = max64(0, now.Unix()-n.LastSeen)
		}
	}
	for i := range links {
		forward := s.metrics[metricKey(links[i].A, links[i].B)]
		reverse := s.metrics[metricKey(links[i].B, links[i].A)]
		freshForward := now.Sub(forward.Seen) < 45*time.Second
		freshReverse := now.Sub(reverse.Seen) < 45*time.Second
		m := linkMetric{}
		if freshForward {
			m.RTTMS = forward.RTTMS
			m.LossRate = forward.LossRate
		}
		if freshReverse {
			if m.RTTMS == 0 {
				m.RTTMS = reverse.RTTMS
			} else if reverse.RTTMS > 0 {
				m.RTTMS = (m.RTTMS + reverse.RTTMS) / 2
			}
			// Loss is directional in practice; the worse view of the link is
			// what a payload stream in either direction will experience.
			m.LossRate = math.Max(m.LossRate, reverse.LossRate)
		}
		baseCost := links[i].Cost
		if baseCost <= 0 {
			baseCost = 1
		}
		if m.RTTMS > 0 {
			links[i].RTTMS = m.RTTMS
			// Keep the configured/manual weight as a base, then scale by the
			// measured latency relative to a 100 ms reference: a 20 ms WAN
			// link pays almost nothing, 100 ms doubles the cost, 300 ms costs
			// 4x and loses every tie against a healthy alternate.
			links[i].Cost = baseCost * math.Min(1+m.RTTMS/rttCostReferenceMS, maxRTTCostFactor)
		} else {
			links[i].Cost = baseCost
		}
		if m.LossRate > 0 {
			links[i].Loss = m.LossRate
			// Expected transmissions per delivery (ETX-style): 10% loss makes
			// the edge ~1.1x, 50% makes it 2x; the cap keeps a nearly dead
			// edge comparable to the down-state penalty instead of infinite.
			loss := math.Min(m.LossRate, 0.95)
			links[i].Cost *= math.Min(1/(1-loss), maxLossCostFactor)
		}
		// New nodes have less observed uptime, so keep them slightly less
		// attractive until they prove stable. The factor converges to 1.
		if ua, oka := uptime[links[i].A]; oka {
			if ub, okb := uptime[links[i].B]; okb {
				hours := float64(min64(ua, ub)) / 3600
				links[i].Cost *= 1 + 1/(1+hours)
			}
		}
		if freshForward && freshReverse && forward.Up && reverse.Up {
			links[i].Status = "up"
		} else if (freshForward && !forward.Up) || (freshReverse && !reverse.Up) {
			links[i].Status = "down"
			links[i].Cost *= 4
		} else {
			links[i].Status = "unknown"
			links[i].Cost *= 2
		}
		// The edge is drawn as a LAN link only when traffic in BOTH fresh
		// directions arrived from local addresses. One confirmed direction
		// decides when the other side has no fresh telemetry; without fresh
		// telemetry the edge is shown as an internet link.
		switch {
		case freshForward && freshReverse:
			links[i].ViaLAN = forward.ViaLAN && reverse.ViaLAN
			if links[i].ViaLAN {
				// A confirmed LAN path carries orders of magnitude more
				// bandwidth than a WAN relay, so halve its cost — using the
				// same both-direction confirmation that decides the display.
				links[i].Cost *= lanCostFactor
			}
		case freshForward:
			links[i].ViaLAN = forward.ViaLAN
		case freshReverse:
			links[i].ViaLAN = reverse.ViaLAN
		default:
			links[i].ViaLAN = false
		}
	}
	return links
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (s *server) consumeInvite(token string) bool {
	if len(token) != 6 {
		return false
	}
	now := time.Now().Unix()
	result, err := s.db.Exec("UPDATE invites SET used_at=? WHERE token=? AND used_at IS NULL AND expires_at>=?", now, token, now)
	if err != nil {
		return false
	}
	count, err := result.RowsAffected()
	return err == nil && count == 1
}

// Five failed invite attempts per IP per 30 seconds keeps a short human
// friendly code practical without making it a brute-force credential.
func (s *server) allowInviteAttempt(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()
	cutoff := now.Add(-30 * time.Second)
	s.inviteMu.Lock()
	defer s.inviteMu.Unlock()
	if s.inviteAttempts == nil {
		s.inviteAttempts = map[string][]time.Time{}
	}
	old := s.inviteAttempts[host]
	kept := old[:0]
	for _, t := range old {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 5 {
		s.inviteAttempts[host] = kept
		return false
	}
	s.inviteAttempts[host] = append(kept, now)
	return true
}

func (s *server) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	accountID, scoped := s.accountIDForRequest(r)
	if r.Method == http.MethodGet {
		query := "SELECT token,created_at,expires_at,used_at FROM invites WHERE expires_at>=?"
		args := []any{time.Now().Unix()}
		if scoped {
			query += " AND owner_id=?"
			args = append(args, accountID)
		}
		query += " ORDER BY created_at DESC"
		rows, err := s.db.Query(query, args...)
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var token string
			var created, expires int64
			var used sql.NullInt64
			if err = rows.Scan(&token, &created, &expires, &used); err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
			out = append(out, map[string]any{"token": token, "created_at": created, "expires_at": expires, "used": used.Valid})
		}
		reply(w, 200, out)
		return
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var token string
	for {
		var raw [6]byte
		if _, err := rand.Read(raw[:]); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		b := make([]byte, 6)
		for i := range b {
			b[i] = alphabet[int(raw[i])%len(alphabet)]
		}
		token = string(b)
		var exists int
		_ = s.db.QueryRow("SELECT 1 FROM invites WHERE token=?", token).Scan(&exists)
		if exists == 0 {
			break
		}
	}
	now := time.Now().Unix()
	var ownerValue any
	if scoped {
		ownerValue = accountID
	}
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at,owner_id) VALUES(?,?,?,?)", token, now, now+60, ownerValue); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "invite_created", "six-digit device invite created")
	s.broadcast("audit")
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": now + 60, "expires_in_seconds": 60})
}

// accountInvite manages high-entropy invitations for human accounts. The
// short setup keys above remain dedicated to enrolling mesh nodes.
func (s *server) accountInvite(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	now := time.Now().Unix()
	if r.Method == http.MethodGet {
		rows, err := s.db.Query("SELECT created_at,expires_at,used_at FROM account_invites WHERE expires_at>=? OR used_at IS NOT NULL ORDER BY created_at DESC LIMIT 50", now)
		if err != nil {
			reply(w, http.StatusInternalServerError, map[string]string{"error": "could not list account invitations"})
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var created, expires int64
			var used sql.NullInt64
			if err = rows.Scan(&created, &expires, &used); err != nil {
				reply(w, http.StatusInternalServerError, map[string]string{"error": "could not list account invitations"})
				return
			}
			out = append(out, map[string]any{"created_at": created, "expires_at": expires, "used": used.Valid})
		}
		reply(w, http.StatusOK, out)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create invitation"})
		return
	}
	expires := now + 24*60*60
	if _, err = s.db.Exec("INSERT INTO account_invites(token_hash,created_at,expires_at) VALUES(?,?,?)", tokenDigest(token), now, expires); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not save invitation"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_invite_created", "account invitation created")
	s.broadcast("audit")
	// The raw token is returned exactly once and is never logged or stored.
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": expires, "expires_in_seconds": 24 * 60 * 60})
}

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
	if err := decodeJSON(w, r, &input); err != nil || (input.Role != "auto" && input.Role != "client" && input.Role != "superpeer") {
		reply(w, 400, map[string]string{"error": "role must be auto, client or superpeer"})
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

// adminGraph validates and saves manually managed mesh links.
func (s *server) adminGraph(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	accountID, scoped := s.accountIDForRequest(r)
	if r.Method == http.MethodGet {
		reply(w, 200, map[string]any{"links": s.manualLinksForAccount(accountID, scoped), "blocked_links": s.blockedLinksForAccount(accountID, scoped)})
		return
	}
	var input struct {
		Links        []link `json:"links"`
		BlockedLinks []link `json:"blocked_links"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	for _, e := range input.Links {
		if e.A == "" || e.B == "" || e.A == e.B || e.Cost <= 0 || e.Cost > 1000 {
			reply(w, 400, map[string]string{"error": "invalid graph link"})
			return
		}
		if scoped && (!s.nodeOwnedByAccount(e.A, accountID) || !s.nodeOwnedByAccount(e.B, accountID)) {
			reply(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}
	}
	for _, e := range input.BlockedLinks {
		if e.A == "" || e.B == "" || e.A == e.B || (scoped && (!s.nodeOwnedByAccount(e.A, accountID) || !s.nodeOwnedByAccount(e.B, accountID))) {
			reply(w, 400, map[string]string{"error": "invalid blocked graph link"})
			return
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()
	if scoped {
		_, err = tx.Exec("DELETE FROM graph_links WHERE a IN (SELECT node_id FROM nodes WHERE owner_id=?) AND b IN (SELECT node_id FROM nodes WHERE owner_id=?)", accountID, accountID)
		if err == nil {
			_, err = tx.Exec("DELETE FROM graph_blocks WHERE a IN (SELECT node_id FROM nodes WHERE owner_id=?) AND b IN (SELECT node_id FROM nodes WHERE owner_id=?)", accountID, accountID)
		}
	} else {
		_, err = tx.Exec("DELETE FROM graph_links")
		if err == nil {
			_, err = tx.Exec("DELETE FROM graph_blocks")
		}
	}
	if err == nil {
		for _, e := range input.Links {
			a, b := e.A, e.B
			if a > b {
				a, b = b, a
			}
			if _, err = tx.Exec("INSERT OR REPLACE INTO graph_links(a,b,cost) VALUES(?,?,?)", a, b, e.Cost); err != nil {
				break
			}
		}
	}
	if err == nil {
		for _, e := range input.BlockedLinks {
			a, b := e.A, e.B
			if a > b {
				a, b = b, a
			}
			if _, err = tx.Exec("INSERT OR IGNORE INTO graph_blocks(a,b) VALUES(?,?)", a, b); err != nil {
				break
			}
		}
	}
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err = tx.Commit(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.invalidateLinkCache()
	s.pushTopologies()
	s.broadcast("topology", "audit")
	reply(w, 200, map[string]any{"links": input.Links, "blocked_links": input.BlockedLinks})
}

func (s *server) manualLinks() []link {
	return s.manualLinksForAccount(0, false)
}

func (s *server) manualLinksForAccount(accountID int64, scoped bool) []link {
	if s.db == nil {
		return []link{}
	}
	query := "SELECT a,b,cost FROM graph_links ORDER BY a,b"
	args := []any{}
	if scoped {
		query = `SELECT g.a,g.b,g.cost FROM graph_links g
			JOIN nodes na ON na.node_id=g.a JOIN nodes nb ON nb.node_id=g.b
			WHERE na.owner_id=? AND nb.owner_id=? ORDER BY g.a,g.b`
		args = []any{accountID, accountID}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return []link{}
	}
	defer rows.Close()
	out := []link{}
	for rows.Next() {
		var e link
		if rows.Scan(&e.A, &e.B, &e.Cost) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *server) blockedLinksForAccount(accountID int64, scoped bool) []link {
	if s.db == nil {
		return []link{}
	}
	query := "SELECT a,b,1.0 FROM graph_blocks ORDER BY a,b"
	args := []any{}
	if scoped {
		query = `SELECT g.a,g.b,1.0 FROM graph_blocks g JOIN nodes na ON na.node_id=g.a JOIN nodes nb ON nb.node_id=g.b WHERE na.owner_id=? AND nb.owner_id=? ORDER BY g.a,g.b`
		args = []any{accountID, accountID}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return []link{}
	}
	defer rows.Close()
	out := []link{}
	for rows.Next() {
		var e link
		if rows.Scan(&e.A, &e.B, &e.Cost) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *server) adminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, adminPageHTML)
}
func (s *server) adminAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	switch r.URL.Path {
	case "/admin.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, adminCSS)
	case "/admin-interactive.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, adminInteractiveCSS)
	case "/admin.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = io.WriteString(w, adminJS)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) rows(query string, args ...any) ([]node, error) {
	rs, e := s.db.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rs.Close()
	a := []node{}
	for rs.Next() {
		var n node
		var relay int
		var lanAddrs string
		if e = rs.Scan(&n.ID, &n.PublicKey, &n.NAT, &n.Role, &n.Endpoint, &n.RequestedRole, &relay, &n.Capacity, &n.LastSeen, &n.CreatedAt, &n.ConnectedAt, &n.MeshIP, &n.GoArch, &lanAddrs); e != nil {
			return nil, e
		}
		n.Relay = relay != 0
		if lanAddrs != "" {
			_ = json.Unmarshal([]byte(lanAddrs), &n.LANAddrs)
		}
		a = append(a, n)
	}
	return a, rs.Err()
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
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
func (s *server) assign(id, requested, nat string, relay bool, capacity int, now int64) (string, error) {
	s.configMu.RLock()
	ttl, auto := s.ttl, s.auto
	s.configMu.RUnlock()
	if requested == "superpeer" {
		return "superpeer", nil
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
func intSqrtCeil(n int) int {
	if n <= 1 {
		return n
	}
	r := 1
	for r*r < n {
		r++
	}
	return r
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// registeredNode combines the three per-heartbeat lookups (node, owner and
// role override) into one indexed query.
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

// register authenticates a node, assigns its mesh address, and renews its lease.
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
	if decodeJSON(w, r, &d) != nil || d.ID == "" || len(d.ID) > 128 || d.Public == "" || len(d.Public) > 256 || d.Endpoint == "" || len(d.Endpoint) > 256 || !(d.NAT == "cone" || d.NAT == "symmetric") || !(d.Role == "auto" || d.Role == "client" || d.Role == "superpeer") {
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

// registrationChangesTopology deliberately ignores LastSeen: a normal
// heartbeat only renews the lease and must not trigger a network-wide
// bootstrap broadcast. A node returning from offline is a topology change
// because it becomes eligible for links again.
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
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sanitizeLanAddrs keeps only well-formed IPv4 "ip:port" entries (max 8) from
// a node's reported LAN address list. Invalid entries are dropped instead of
// rejecting the whole registration: a node must never fail its heartbeat
// because of an odd interface configuration.
func sanitizeLanAddrs(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), port))
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// rendezvousRegister coordinates peer discovery for NAT traversal.
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

// rendezvousWait holds a request until the matching peer is ready.
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
func topologyVersion(nodes []node) string {
	var a []string
	for _, n := range nodes {
		a = append(a, strings.Join([]string{n.ID, n.PublicKey, n.NAT, n.Role, n.Endpoint, n.MeshIP, strconv.Itoa(n.Capacity)}, ":"))
	}
	h := sha256.Sum256([]byte(strings.Join(a, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// bootstrapTopologyVersion fingerprints everything that can change a node's
// forwarding view. topologyVersion is intentionally kept as the link-cache
// key, while this version also covers enriched network metadata and the
// effective edges. Otherwise a pushed manual/config/route change can carry
// the old version and be silently discarded by clients.
func bootstrapTopologyVersion(nodes []node, links []link) string {
	// Lease refreshes and uptime do not change the forwarding view. Hash a
	// copy so live status fields remain available in full/admin responses.
	nodes = append([]node(nil), nodes...)
	// Cache hits may represent an empty edge list as nil rather than [].
	links = append([]link(nil), links...)
	for i := range nodes {
		nodes[i].LastSeen = 0
		nodes[i].UptimeSeconds = 0
	}
	b, _ := json.Marshal(struct {
		Nodes []node `json:"nodes"`
		Links []link `json:"links"`
	}{nodes, links})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}
func weightedPeerOrder(client node, peers []node) []node {
	rank := append([]node(nil), peers...)
	sort.Slice(rank, func(i, j int) bool {
		// Weighted rendezvous hashing gives every client a stable preference
		// order. Capacity raises a relay's chance without globally reshuffling
		// assignments when an unrelated node appears or disappears.
		si := rendezvousScore(client.ID, rank[i].ID, rank[i].Capacity)
		sj := rendezvousScore(client.ID, rank[j].ID, rank[j].Capacity)
		if si != sj {
			return si < sj
		}
		return rank[i].ID < rank[j].ID
	})
	return rank
}
func rendezvousScore(clientID, peerID string, capacity int) uint64 {
	if capacity < 1 {
		capacity = 1
	}
	h := sha256.Sum256([]byte(clientID + ":" + peerID))
	// A lower weighted score wins. Do not use endpoint data: it changes after
	// NAT rebinding and would needlessly restart symmetric-NAT connections.
	return binary.BigEndian.Uint64(h[:8]) / uint64(capacity)
}
func (s *server) telemetryPeerOrder(client node, peers []node) []node {
	rank := append([]node(nil), peers...)
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	sort.Slice(rank, func(i, j int) bool {
		a, b := s.metrics[metricKey(client.ID, rank[i].ID)], s.metrics[metricKey(client.ID, rank[j].ID)]
		state := func(m linkMetric) int {
			if time.Since(m.Seen) >= 45*time.Second {
				return 1 // unknown: preferable to a recently confirmed failure
			}
			if m.Up {
				return 2
			}
			return 0
		}
		if stateA, stateB := state(a), state(b); stateA != stateB {
			return stateA > stateB
		}
		si := rendezvousScore(client.ID, rank[i].ID, rank[i].Capacity)
		sj := rendezvousScore(client.ID, rank[j].ID, rank[j].Capacity)
		if si != sj {
			return si < sj
		}
		return rank[i].ID < rank[j].ID
	})
	return rank
}

// links builds the forwarding graph from policy and observed link metrics.
//
// Invariants, in priority order:
//  1. Reachability: the effective graph over all online nodes is always
//     connected. Manual islands, blocked edges, and superpeers going offline
//     are healed by bridging components instead of stranding clients.
//  2. Minimal churn: weighted rendezvous hashing keeps client assignments
//     stable when unrelated nodes join or leave, and the backbone ring only
//     rewires the edges adjacent to the position that changed.
//  3. Redundancy: the backbone keeps at least ring degree (2), so the mesh
//     survives the loss of any single superpeer without a partition.
func (s *server) links(nodes []node) []link {
	blocked := s.blockedEdgeSet(nodes)
	s.configMu.RLock()
	backboneDegree := s.backboneDegree
	s.configMu.RUnlock()
	if manual := s.manualLinksForNodes(nodes); len(manual) > 0 {
		// Blocked edges are removed before client attachment so a blocked
		// manual link never consumes a client's automatic link budget.
		out := removeBlockedEdges(manual, blocked)
		out = s.addAutomaticClientLinks(out, nodes, superpeerNodes(nodes), blocked)
		return s.decorateLinks(s.ensureConnected(removeBlockedEdges(out, blocked), nodes, blocked), nodes)
	}
	superpeers := superpeerNodes(nodes)
	var out []link
	if len(superpeers) > 1 {
		out = backboneLinks(superpeers, backboneDegree)
	}
	// Clients attach to superpeers while any are online. A pure-client mesh
	// (no relay-capable node available, e.g. right after the last superpeer
	// leaves, or in small standalone setups) degenerates to peer-to-peer
	// attachment instead of an empty, unreachable graph.
	peers := superpeers
	if len(peers) == 0 {
		peers = nodes
	}
	out = s.addAutomaticClientLinks(out, nodes, peers, blocked)
	return s.decorateLinks(s.ensureConnected(removeBlockedEdges(out, blocked), nodes, blocked), nodes)
}

// backboneLinks wires the superpeer backbone as a ring over sorted node IDs
// plus redundant chords. The ring alone guarantees connectivity and only
// changes the two edges adjacent to a position when one superpeer joins or
// leaves; chords shorten paths and add redundancy but are never required for
// reachability. Degree is floored at 2: honoring degree 1 produced a perfect
// matching (or, with an odd peer count, no backbone at all), silently
// partitioning the mesh after the first superpeer failure.
func backboneLinks(superpeers []node, degree int) []link {
	n := len(superpeers)
	if n < 2 {
		return nil
	}
	if degree < 2 {
		degree = 2
	}
	if degree > n-1 {
		degree = n - 1
	}
	seen := make(map[string]bool, n*degree)
	out := make([]link, 0, n*degree)
	add := func(a, b string) {
		if a > b {
			a, b = b, a
		}
		if a == b {
			return
		}
		k := a + ":" + b
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, link{A: a, B: b, Cost: 1})
	}
	for i := range superpeers {
		add(superpeers[i].ID, superpeers[(i+1)%n].ID)
	}
	for step := 2; step <= degree/2; step++ {
		for i := range superpeers {
			add(superpeers[i].ID, superpeers[(i+step)%n].ID)
		}
	}
	if degree%2 == 1 {
		half := n / 2
		for i := 0; i < half; i++ {
			add(superpeers[i].ID, superpeers[i+half].ID)
		}
	}
	return out
}

// ensureConnected is the safety net that keeps the mesh reachable: after all
// other graph rules (manual edits, blocked pairs, departed nodes) have been
// applied, any remaining disconnected components are bridged with the
// cheapest deterministic edges. Repairs are idempotent and independent of
// live telemetry, so repeated builds produce the same bridges. Explicitly
// blocked pairs are never restored: if admin policy blocks every candidate
// pair between two components, those components stay disconnected.
func (s *server) ensureConnected(edges []link, nodes []node, blocked map[string]bool) []link {
	if len(nodes) < 2 {
		return edges
	}
	parent := make(map[string]string, len(nodes))
	for _, n := range nodes {
		parent[n.ID] = n.ID
	}
	var find func(string) string
	find = func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	for _, e := range edges {
		if _, ok := parent[e.A]; !ok {
			continue
		}
		if _, ok := parent[e.B]; !ok {
			continue
		}
		if ra, rb := find(e.A), find(e.B); ra != rb {
			parent[ra] = rb
		}
	}
	components := map[string][]node{}
	for _, n := range nodes {
		root := find(n.ID)
		components[root] = append(components[root], n)
	}
	if len(components) <= 1 {
		return edges
	}
	// Deterministic order keeps the repair reproducible across builds.
	roots := make([]string, 0, len(components))
	for root := range components {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	out := append([]link(nil), edges...)
	for i := 1; i < len(roots); i++ {
		a, b, ok := bridgeNodes(components[roots[i-1]], components[roots[i]], blocked)
		if !ok {
			continue
		}
		out = append(out, link{A: a.ID, B: b.ID, Cost: 1.25})
	}
	return out
}

// bridgeNodes picks the pair of nodes joining two components. Superpeers are
// preferred on both ends (client degree stays low), then weighted rendezvous
// hashing breaks ties so the same components always yield the same bridge,
// biased toward higher-capacity relays. Blocked pairs are skipped; ok is
// false when every possible pair is blocked.
func bridgeNodes(a, b []node, blocked map[string]bool) (node, node, bool) {
	tier := func(n node) int {
		if n.Role == "superpeer" {
			return 0
		}
		return 1
	}
	var bestA, bestB node
	bestTier, bestScore := 0, uint64(0)
	found := false
	for _, x := range a {
		for _, y := range b {
			if blocked[edgeKey(x.ID, y.ID)] {
				continue
			}
			t := tier(x) + tier(y)
			s1 := rendezvousScore(x.ID, y.ID, x.Capacity)
			s2 := rendezvousScore(y.ID, x.ID, y.Capacity)
			lo, hi := s1, s2
			if hi < lo {
				lo, hi = hi, lo
			}
			idPair := x.ID + "\x00" + y.ID
			bestPair := bestA.ID + "\x00" + bestB.ID
			if !found || t < bestTier || (t == bestTier && (lo < bestScore || (lo == bestScore && idPair < bestPair))) {
				bestA, bestB, bestTier, bestScore, found = x, y, t, lo, true
			}
		}
	}
	return bestA, bestB, found
}

// superpeerNodes returns the online superpeers in directory order. Nodes are
// loaded ORDER BY node_id, so the backbone ring is deterministic.
func superpeerNodes(nodes []node) []node {
	var sp []node
	for _, n := range nodes {
		if n.Role == "superpeer" {
			sp = append(sp, n)
		}
	}
	return sp
}

// blockedEdgeSet collects blocked pairs among the online nodes once per graph
// build instead of once per filtering pass.
func (s *server) blockedEdgeSet(nodes []node) map[string]bool {
	blocked := make(map[string]bool)
	for _, e := range s.blockedLinksForNodes(nodes) {
		blocked[edgeKey(e.A, e.B)] = true
	}
	return blocked
}

func removeBlockedEdges(edges []link, blocked map[string]bool) []link {
	if len(blocked) == 0 {
		return edges
	}
	out := edges[:0]
	for _, e := range edges {
		if !blocked[edgeKey(e.A, e.B)] {
			out = append(out, e)
		}
	}
	return out
}

func (s *server) blockedLinksForNodes(nodes []node) []link {
	allowed := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	out := []link{}
	for _, e := range s.blockedLinksForAccount(0, false) {
		if allowed[e.A] && allowed[e.B] {
			out = append(out, e)
		}
	}
	return out
}

// cachedTopologyLinks shares the graph calculation across all bootstrap
// responses in one topology push. The directory remains freshly loaded per
// request, so endpoint and lease data are never served from this cache.
func (s *server) cachedTopologyLinks(nodes []node) []link {
	// The metric stamp only changes when a link appears or flips up/down, so
	// steady-state telemetry keeps cache hits while still invalidating on
	// meaningful health changes.
	key := topologyVersion(nodes) + "#" + strconv.FormatUint(s.metricStamp.Load(), 10)
	s.topologyMu.Lock()
	defer s.topologyMu.Unlock()
	if entry, ok := s.linkCache[key]; ok && entry.epoch == s.cacheEpoch {
		return append([]link(nil), entry.links...)
	}
	links := s.links(nodes)
	if s.linkCache == nil {
		s.linkCache = make(map[string]cachedLinks)
	}
	if len(s.linkCache) > 64 {
		s.linkCache = nil
	}
	s.linkCache[key] = cachedLinks{epoch: s.cacheEpoch, links: append([]link(nil), links...)}
	return links
}

func (s *server) invalidateLinkCache() {
	s.topologyMu.Lock()
	s.cacheEpoch++
	s.linkCache = nil
	s.topologyMu.Unlock()
}

func (s *server) manualLinksForNodes(nodes []node) []link {
	allowed := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	out := []link{}
	for _, e := range s.manualLinks() {
		if allowed[e.A] && allowed[e.B] {
			out = append(out, e)
		}
	}
	return out
}

func edgeKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + ":" + b
}

// addAutomaticClientLinks preserves managed backbone edges while attaching
// every client to its preferred peers in weighted rendezvous order: normally
// the superpeers, or the whole directory when no superpeer is online. Blocked
// pairs are skipped outright so they never consume a client's link budget,
// and the wanted count is floored at one so a blocked first choice or a
// misconfiguration still leaves the client reachable.
func (s *server) addAutomaticClientLinks(out []link, nodes, peers []node, blocked map[string]bool) []link {
	if len(peers) == 0 {
		return out
	}
	s.configMu.RLock()
	clientLinks, symmetricLinks := s.clientLinks, s.symmetricLinks
	s.configMu.RUnlock()
	for _, client := range nodes {
		if client.Role != "client" {
			continue
		}
		want := clientLinks
		if client.NAT == "symmetric" {
			want = symmetricLinks
		}
		if want < 1 {
			want = 1
		}
		connected := map[string]bool{}
		for _, edge := range out {
			if edge.A == client.ID {
				connected[edge.B] = true
			}
			if edge.B == client.ID {
				connected[edge.A] = true
			}
		}
		count := 0
		for _, peer := range peers {
			if peer.ID != client.ID && connected[peer.ID] {
				count++
			}
		}
		for _, peer := range s.telemetryPeerOrder(client, peers) {
			if count >= want {
				break
			}
			if peer.ID == client.ID || connected[peer.ID] || blocked[edgeKey(client.ID, peer.ID)] {
				continue
			}
			out = append(out, link{A: client.ID, B: peer.ID, Cost: 1 + float64(count)/10})
			connected[peer.ID] = true
			count++
		}
	}
	return out
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// bootstrap returns the topology and connection details a node needs to join.
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

// adminRevoked lists banned node identities shown in the access page.
