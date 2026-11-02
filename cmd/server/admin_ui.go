package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

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
