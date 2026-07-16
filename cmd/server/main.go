// Command server is the HTTP control plane. It intentionally never forwards user traffic.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"home-udp-mesh/internal/protocol"
	_ "modernc.org/sqlite"
)

type node struct {
	ID                  string `json:"node_id"`
	PublicKey           string `json:"public_key"`
	NAT                 string `json:"nat_type"`
	Role                string `json:"role"`
	Endpoint            string `json:"endpoint"`
	Capacity            int    `json:"capacity"`
	MeshIP              string `json:"mesh_ip"`
	RequestedRole       string
	Relay               bool
	LastSeen, CreatedAt int64
}
type link struct {
	A    string  `json:"a"`
	B    string  `json:"b"`
	Cost float64 `json:"cost"`
}
type server struct {
	db      *sql.DB
	token   string
	network *net.IPNet
	ttl     int64
	auto    int

	sessionsMu sync.Mutex
	sessions   map[string]map[string]*rendezvousPeer
}

type rendezvousPeer struct {
	endpoint string
	natType  string
	status   string
	other    string
	otherNAT string
	ready    chan struct{}
}

func envInt(name string, fallback int) int {
	if v, e := strconv.Atoi(os.Getenv(name)); e == nil && v > 0 {
		return v
	}
	return fallback
}
func main() {
	dsn := os.Getenv("MESH_DATABASE")
	if dsn == "" {
		dsn = "mesh.db"
	}
	db, e := sql.Open("sqlite", dsn)
	if e != nil {
		log.Fatal(e)
	}
	s := &server{db: db, token: os.Getenv("MESH_NETWORK_TOKEN"), ttl: int64(envInt("MESH_NODE_TTL_SECONDS", 45)), auto: envInt("MESH_AUTO_SUPERPEERS", 2), sessions: map[string]map[string]*rendezvousPeer{}}
	_, s.network, _ = net.ParseCIDR(value("MESH_IP_NETWORK", "10.77.0.0/24"))
	if e = s.init(); e != nil {
		log.Fatal(e)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("GET /v1/bootstrap/{node_id}", s.bootstrap)
	mux.HandleFunc("POST /v1/services", s.service)
	mux.HandleFunc("GET /v1/services/{node_id}/{name}", s.serviceDetails)
	// Legacy endpoints intentionally stay unauthenticated: the experimental
	// punch client predates the mesh network token and can use this coordinator.
	mux.HandleFunc("POST /register", s.rendezvousRegister)
	mux.HandleFunc("GET /wait", s.rendezvousWait)
	port := value("MESH_PORT", "8001")
	log.Printf("[SERVER] starting on 0.0.0.0:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
func value(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func (s *server) init() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS nodes (node_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,nat_type TEXT NOT NULL,role TEXT NOT NULL,endpoint TEXT NOT NULL,requested_role TEXT NOT NULL DEFAULT 'auto',relay_capable INTEGER NOT NULL DEFAULT 1,capacity INTEGER NOT NULL DEFAULT 1,last_seen INTEGER NOT NULL,created_at INTEGER NOT NULL,mesh_ip TEXT);CREATE TABLE IF NOT EXISTS services (node_id TEXT NOT NULL,name TEXT NOT NULL,target_host TEXT NOT NULL,target_port INTEGER NOT NULL,allowed_nodes TEXT NOT NULL DEFAULT '*',PRIMARY KEY(node_id,name));`)
	if err != nil {
		return err
	}
	rows, err := s.db.Query("PRAGMA table_info(nodes)")
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !columns["mesh_ip"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN mesh_ip TEXT"); err != nil {
			return err
		}
	}
	if !columns["requested_role"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN requested_role TEXT"); err != nil {
			return err
		}
		if _, err = s.db.Exec("UPDATE nodes SET requested_role = CASE WHEN role = 'superpeer' THEN 'superpeer' ELSE 'auto' END"); err != nil {
			return err
		}
	}
	if !columns["relay_capable"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN relay_capable INTEGER NOT NULL DEFAULT 1"); err != nil {
			return err
		}
	}
	return nil
}
func (s *server) auth(w http.ResponseWriter, r *http.Request) bool {
	if s.token != "" && r.Header.Get("X-Mesh-Token") != s.token {
		reply(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func (s *server) rows(query string, args ...any) ([]node, error) {
	rs, e := s.db.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rs.Close()
	var a []node
	for rs.Next() {
		var n node
		var relay int
		if e = rs.Scan(&n.ID, &n.PublicKey, &n.NAT, &n.Role, &n.Endpoint, &n.RequestedRole, &relay, &n.Capacity, &n.LastSeen, &n.CreatedAt, &n.MeshIP); e != nil {
			return nil, e
		}
		n.Relay = relay != 0
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
	if requested == "superpeer" {
		return "superpeer", nil
	}
	if requested == "client" || nat != "cone" || !relay {
		return "client", nil
	}
	all, e := s.rows("SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=? AND node_id!=?", now-s.ttl, id)
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
	slots := s.auto - manual
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
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var d struct {
		ID       string `json:"node_id"`
		Public   string `json:"public_key"`
		NAT      string `json:"nat_type"`
		Role     string `json:"role"`
		Endpoint string `json:"endpoint"`
		MeshIP   string `json:"mesh_ip"`
		Capacity int    `json:"capacity"`
		Relay    *bool  `json:"relay_capable"`
	}
	if json.NewDecoder(r.Body).Decode(&d) != nil || d.ID == "" || d.Public == "" || d.Endpoint == "" || !(d.NAT == "cone" || d.NAT == "symmetric") || !(d.Role == "auto" || d.Role == "client" || d.Role == "superpeer") {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
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
	var old sql.NullString
	s.db.QueryRow("SELECT mesh_ip FROM nodes WHERE node_id=?", d.ID).Scan(&old)
	ip := d.MeshIP
	if ip == "" && old.Valid {
		ip = old.String
	}
	if ip == "" {
		ip, e = s.allocate()
		if e != nil {
			reply(w, 500, map[string]any{"error": e.Error()})
			return
		}
	}
	var owner string
	s.db.QueryRow("SELECT node_id FROM nodes WHERE mesh_ip=? AND node_id!=?", ip, d.ID).Scan(&owner)
	if owner != "" {
		reply(w, 409, map[string]any{"error": "mesh_ip is already assigned"})
		return
	}
	role, e := s.assign(d.ID, d.Role, d.NAT, relay, d.Capacity, now)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	_, e = s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET public_key=excluded.public_key,nat_type=excluded.nat_type,role=excluded.role,endpoint=excluded.endpoint,requested_role=excluded.requested_role,relay_capable=excluded.relay_capable,capacity=excluded.capacity,last_seen=excluded.last_seen,mesh_ip=excluded.mesh_ip`, d.ID, d.Public, d.NAT, role, d.Endpoint, d.Role, boolInt(relay), d.Capacity, now, now, ip)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	log.Printf("[SERVER] register node=%s role=%s mesh_ip=%s", d.ID[:8], role, ip)
	reply(w, 200, map[string]any{"status": "ok", "mesh_ip": ip, "mesh_network": s.network.String(), "assigned_role": role})
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *server) rendezvousRegister(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Session  string `json:"session"`
		ID       string `json:"id"`
		External string `json:"external"`
		NATType  string `json:"nat_type"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil || request.Session == "" || request.ID == "" || request.External == "" || (request.NATType != "cone" && request.NATType != "symmetric") {
		reply(w, http.StatusBadRequest, map[string]any{"error": "missing or invalid fields"})
		return
	}
	if _, _, err := net.SplitHostPort(request.External); err != nil {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid external endpoint"})
		return
	}

	s.sessionsMu.Lock()
	peers := s.sessions[request.Session]
	if peers == nil {
		peers = map[string]*rendezvousPeer{}
		s.sessions[request.Session] = peers
	}
	peers[request.ID] = &rendezvousPeer{endpoint: request.External, natType: request.NATType, status: "waiting", ready: make(chan struct{})}
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
func links(nodes []node) []link {
	var sp []node
	for _, n := range nodes {
		if n.Role == "superpeer" {
			sp = append(sp, n)
		}
	}
	var out []link
	degree := min(6, len(sp)-1)
	seen := map[string]bool{}
	for i, n := range sp {
		for step := 1; step <= degree/2; step++ {
			a, b := n.ID, sp[(i+step)%len(sp)].ID
			if a > b {
				a, b = b, a
			}
			k := a + ":" + b
			if !seen[k] {
				seen[k] = true
				out = append(out, link{a, b, 1})
			}
		}
		if degree%2 == 1 && len(sp)%2 == 0 {
			a, b := n.ID, sp[(i+len(sp)/2)%len(sp)].ID
			if a > b {
				a, b = b, a
			}
			k := a + ":" + b
			if !seen[k] {
				seen[k] = true
				out = append(out, link{a, b, 1})
			}
		}
	}
	assigned := map[string]int{}
	for _, n := range nodes {
		if n.Role != "client" {
			continue
		}
		rank := append([]node(nil), sp...)
		sort.Slice(rank, func(i, j int) bool {
			li := float64(assigned[rank[i].ID]) / float64(max(1, rank[i].Capacity))
			lj := float64(assigned[rank[j].ID]) / float64(max(1, rank[j].Capacity))
			if li != lj {
				return li < lj
			}
			if rank[i].Capacity != rank[j].Capacity {
				return rank[i].Capacity > rank[j].Capacity
			}
			return rank[i].ID < rank[j].ID
		})
		for i, p := range rank[:min(3, len(rank))] {
			assigned[p.ID]++
			out = append(out, link{n.ID, p.ID, 1 + float64(i)/10})
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
func (s *server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	all, e := s.rows("SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=? ORDER BY node_id", time.Now().Unix()-s.ttl)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
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
	ls := links(all)
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
	rs, _ := s.db.Query("SELECT node_id,name FROM services ORDER BY node_id,name")
	var services []map[string]string
	for rs.Next() {
		var n, x string
		rs.Scan(&n, &x)
		services = append(services, map[string]string{"node_id": n, "name": x})
	}
	rs.Close()
	reply(w, 200, map[string]any{"topology_version": topologyVersion(all), "self": self, "neighbors": peers, "directory": all, "backbone_links": ls, "services": services, "graph_update_mode": "reserved"})
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
	if json.NewDecoder(r.Body).Decode(&d) != nil || d.Node == "" || d.Name == "" || d.Host == "" || d.Port < 1 || d.Port > 65535 {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
		return
	}
	var x int
	e := s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", d.Node).Scan(&x)
	if e != nil {
		reply(w, 404, map[string]any{"error": "unknown node"})
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
