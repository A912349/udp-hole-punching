package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func (s *server) adminRevoked(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	rows, err := s.db.Query("SELECT node_id,reason,revoked_at FROM revoked_nodes ORDER BY revoked_at DESC LIMIT 500")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	for rows.Next() {
		var id, reason string
		var at int64
		if rows.Scan(&id, &reason, &at) == nil {
			list = append(list, map[string]any{"node_id": id, "reason": reason, "revoked_at": at})
		}
	}
	reply(w, 200, map[string]any{"revoked": list})
}

// adminUnban lifts the ban so the node identity may enroll again (its old
// per-node token was destroyed together with the node row, so a fresh setup
// key is required either way).
func (s *server) adminUnban(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	res, err := s.db.Exec("DELETE FROM revoked_nodes WHERE node_id=?", id)
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		reply(w, 404, map[string]string{"error": "node is not banned"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_unbanned", id)
	s.broadcast("audit")
	reply(w, 200, map[string]string{"status": "unbanned"})
}

// firewallPortList normalizes user-supplied port entries into the canonical
// stored form: sorted, deduplicated "port/proto" strings. A bare number
// expands to both TCP and UDP; the protocol part is case-insensitive.
func firewallPortList(input []string) ([]string, error) {
	out := map[string]bool{}
	for _, raw := range input {
		entry := strings.TrimSpace(strings.ToLower(raw))
		if entry == "" {
			continue
		}
		port, proto := entry, "both"
		if i := strings.IndexByte(entry, '/'); i >= 0 {
			port, proto = entry[:i], entry[i+1:]
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		switch proto {
		case "tcp":
			out[fmt.Sprintf("%d/tcp", n)] = true
		case "udp":
			out[fmt.Sprintf("%d/udp", n)] = true
		case "both", "":
			out[fmt.Sprintf("%d/tcp", n)] = true
			out[fmt.Sprintf("%d/udp", n)] = true
		default:
			return nil, fmt.Errorf("unsupported protocol in %q (use tcp or udp)", raw)
		}
	}
	list := make([]string, 0, len(out))
	for p := range out {
		list = append(list, p)
	}
	sort.Strings(list)
	return list, nil
}

// loadFirewall returns the mesh firewall policy of a node; nodes without a
// stored row run in the permissive default mode.
func (s *server) loadFirewall(id string) firewallConfig {
	fw := firewallConfig{Mode: "allow_all", Ports: []string{}}
	var mode, ports string
	if err := s.db.QueryRow("SELECT mode,ports FROM node_firewall WHERE node_id=?", id).Scan(&mode, &ports); err == nil {
		if mode == "whitelist" {
			fw.Mode = "whitelist"
		}
		var list []string
		if json.Unmarshal([]byte(ports), &list) == nil {
			if normalized, e := firewallPortList(list); e == nil {
				fw.Ports = normalized
			}
		}
	}
	return fw
}

func (s *server) adminFirewallGet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	reply(w, 200, s.loadFirewall(id))
}

// adminFirewallSet configures the mesh firewall of a node. The policy is
// enforced by the node itself on the TUN ingress path (it arrives with the
// bootstrap/push topology), so LAN forwarding and outbound traffic are
// unaffected and no OS-level rules are touched.
func (s *server) adminFirewallSet(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var d struct {
		Mode  string   `json:"mode"`
		Ports []string `json:"ports"`
	}
	if decodeJSON(w, r, &d) != nil {
		reply(w, 400, map[string]string{"error": "invalid firewall settings"})
		return
	}
	d.Mode = strings.TrimSpace(strings.ToLower(d.Mode))
	if d.Mode != "allow_all" && d.Mode != "whitelist" {
		reply(w, 400, map[string]string{"error": "mode must be allow_all or whitelist"})
		return
	}
	ports, err := firewallPortList(d.Ports)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if len(ports) > 256 {
		reply(w, 400, map[string]string{"error": "too many ports (max 256)"})
		return
	}
	raw, _ := json.Marshal(ports)
	if _, err := s.db.Exec(`INSERT INTO node_firewall(node_id,mode,ports,updated_at) VALUES(?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET mode=excluded.mode,ports=excluded.ports,updated_at=excluded.updated_at`, id, d.Mode, string(raw), time.Now().Unix()); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "firewall_updated", fmt.Sprintf("node=%s mode=%s ports=%s", id, d.Mode, string(raw)))
	s.pushTopologies()
	s.broadcast("topology", "audit")
	reply(w, 200, firewallConfig{Mode: d.Mode, Ports: ports})
}

// adminForwards lists the service-forwarding rules visible to this account.
func (s *server) adminForwards(w http.ResponseWriter, r *http.Request) {
	// This endpoint is used by the admin UI, so account sessions must be
	// accepted in addition to the legacy network token. Mutating requests are
	// protected by adminAuth's CSRF check for session-authenticated users.
	if !s.adminAuth(w, r) {
		return
	}
	accountID, scoped := s.accountIDForRequest(r)
	if r.Method == http.MethodGet {
		q := `SELECT f.id,f.source_node_id,f.listen_host,f.listen_port,f.target_node_id,f.target_host,f.target_port FROM port_forwards f`
		args := []any{}
		if scoped {
			q += ` JOIN nodes n ON n.node_id=f.source_node_id WHERE n.owner_id=?`
			args = append(args, accountID)
		}
		q += ` ORDER BY f.id DESC`
		rows, err := s.db.Query(q, args...)
		if err != nil {
			reply(w, 500, map[string]any{"error": err.Error()})
			return
		}
		defer rows.Close()
		out := []portForward{}
		for rows.Next() {
			var f portForward
			if rows.Scan(&f.ID, &f.Source, &f.ListenHost, &f.ListenPort, &f.Target, &f.TargetHost, &f.TargetPort) == nil {
				out = append(out, f)
			}
		}
		reply(w, 200, out)
		return
	}
	var f portForward
	if decodeJSON(w, r, &f) != nil || f.Source == "" || f.Target == "" || f.TargetHost == "" || f.ListenPort < 1 || f.ListenPort > 65535 || f.TargetPort < 1 || f.TargetPort > 65535 {
		reply(w, 400, map[string]any{"error": "invalid forwarding rule"})
		return
	}
	if f.ListenHost == "" {
		f.ListenHost = "127.0.0.1"
	}
	if ip := net.ParseIP(f.ListenHost); ip == nil || !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsGlobalUnicast() {
		reply(w, 400, map[string]any{"error": "listener must be an IP address"})
		return
	}
	if !s.requireNodeAccess(w, r, f.Source) || !s.requireNodeAccess(w, r, f.Target) {
		return
	}
	if _, err := s.db.Exec(`INSERT INTO port_forwards(source_node_id,listen_host,listen_port,target_node_id,target_host,target_port) VALUES(?,?,?,?,?,?)`, f.Source, f.ListenHost, f.ListenPort, f.Target, f.TargetHost, f.TargetPort); err != nil {
		reply(w, 409, map[string]any{"error": "listener is already configured or node is unknown"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "port_forward_created", f.Source+":"+strconv.Itoa(f.ListenPort)+" -> "+f.Target+":"+f.TargetHost+":"+strconv.Itoa(f.TargetPort))
	s.broadcast("forwards", "audit")
	s.pushTopologies()
	reply(w, 201, map[string]any{"status": "ok"})
}
func (s *server) adminForward(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		reply(w, 400, map[string]any{"error": "invalid forwarding rule"})
		return
	}
	var source string
	if err = s.db.QueryRow(`SELECT source_node_id FROM port_forwards WHERE id=?`, id).Scan(&source); err != nil {
		reply(w, 404, map[string]any{"error": "forwarding rule not found"})
		return
	}
	if !s.requireNodeAccess(w, r, source) {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM port_forwards WHERE id=?`, id)
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "port_forward_removed", strconv.FormatInt(id, 10))
	s.broadcast("forwards", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]any{"status": "ok"})
}
func (s *server) service(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var d struct {
		Node    string `json:"node_id"`
		Name    string `json:"name"`
		Host    string `json:"target_host"`
		Port    int    `json:"target_port"`
		Allowed string `json:"allowed_nodes"`
	}
	if decodeJSON(w, r, &d) != nil || d.Node == "" || len(d.Node) > 128 || d.Name == "" || len(d.Name) > 128 || d.Host == "" || len(d.Host) > 253 || d.Port < 1 || d.Port > 65535 {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
		return
	}
	var x int
	e := s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", d.Node).Scan(&x)
	if e != nil {
		reply(w, 404, map[string]any{"error": "unknown node"})
		return
	}
	if !s.requireNodeAccess(w, r, d.Node) {
		return
	}
	if d.Allowed == "" {
		d.Allowed = "*"
	}
	_, e = s.db.Exec(`INSERT INTO services(node_id,name,target_host,target_port,allowed_nodes) VALUES(?,?,?,?,?) ON CONFLICT(node_id,name) DO UPDATE SET target_host=excluded.target_host,target_port=excluded.target_port,allowed_nodes=excluded.allowed_nodes`, d.Node, d.Name, d.Host, d.Port, d.Allowed)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	reply(w, 200, map[string]any{"status": "ok"})
}
func (s *server) serviceDetails(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	if !s.requireNodeAccess(w, r, r.PathValue("node_id")) {
		return
	}
	var d struct {
		Node, Name, Host, Allowed string
		Port                      int
	}
	e := s.db.QueryRow("SELECT node_id,name,target_host,target_port,allowed_nodes FROM services WHERE node_id=? AND name=?", r.PathValue("node_id"), r.PathValue("name")).Scan(&d.Node, &d.Name, &d.Host, &d.Port, &d.Allowed)
	if e != nil {
		reply(w, 404, map[string]any{"error": "service not found"})
		return
	}
	reply(w, 200, map[string]any{"node_id": d.Node, "name": d.Name, "target_host": d.Host, "target_port": d.Port, "allowed_nodes": d.Allowed})
}
