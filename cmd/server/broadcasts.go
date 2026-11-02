package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
func superpeerNodes(nodes []node) []node {
	var sp []node
	for _, n := range nodes {
		if n.Role == "superpeer" {
			sp = append(sp, n)
		}
	}
	return sp
}
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
