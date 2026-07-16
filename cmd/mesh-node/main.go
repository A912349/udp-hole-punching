// Command mesh-node runs an encrypted UDP overlay endpoint and optional service gateway.
package main

import (
	"container/heap"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"home-udp-mesh/internal/protocol"
)

const (
	keepAlive   = 10 * time.Second
	refresh     = 5 * time.Second
	heartbeat   = 15 * time.Second
	linkTimeout = 30 * time.Second
	maxRequest  = 32000
	maxResponse = 48000
	fastMagic   = "MIP1"
	fastMAC     = 32
	fastHeader  = 49
	maxTUN      = 1279
)

type config struct {
	server, token, role, nat, bind, endpoint, meshIP, tun, state, call, requestFile string
	port, capacity, prefix                                                          int
	noRelay, autoTUN                                                                bool
	services, allows                                                                multi
}
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type peer struct {
	ID       string `json:"node_id"`
	Public   string `json:"public_key"`
	NAT      string `json:"nat_type"`
	Role     string `json:"role"`
	Endpoint string `json:"endpoint"`
	Capacity int    `json:"capacity"`
	MeshIP   string `json:"mesh_ip"`
	last     net.Addr
	lastRX   time.Time
	up       bool
}
type edge struct {
	A    string  `json:"a"`
	B    string  `json:"b"`
	Cost float64 `json:"cost"`
}
type topology struct {
	Version   string `json:"topology_version"`
	Self      peer   `json:"self"`
	Neighbors []peer `json:"neighbors"`
	Directory []peer `json:"directory"`
	Links     []edge `json:"backbone_links"`
}
type pending struct {
	done   chan serviceResult
	result serviceResult
}
type serviceResult struct {
	Data  string `json:"data"`
	Error string `json:"error"`
}
type node struct {
	c         config
	id        *protocol.Identity
	key       []byte
	conn      *net.UDPConn
	client    *http.Client
	mu        sync.RWMutex
	dir       map[string]*peer
	neighbors map[string]*peer
	links     []edge
	routes    map[string]string
	seen      map[string]time.Time
	pending   map[string]chan serviceResult
	services  map[string]string
	allow     map[string]bool
	stop      context.CancelFunc
	tun       *os.File
}

func main() {
	c := parse()
	if len(c.token) < 24 {
		log.Fatal("--network-token must be at least 24 characters")
	}
	n, e := newNode(c)
	if e != nil {
		log.Fatal(e)
	}
	defer n.close()
	log.Printf("[%s] Mesh node %s", n.id.ID[:8], n.id.ID)
	if e = n.start(); e != nil {
		log.Fatal(e)
	}
	if c.call != "" {
		parts := strings.SplitN(c.call, ":", 2)
		if len(parts) != 2 {
			log.Fatal("--call must be NODE_ID:SERVICE")
		}
		var b []byte
		if c.requestFile != "" {
			b, e = os.ReadFile(c.requestFile)
		} else {
			b, e = io.ReadAll(os.Stdin)
		}
		if e != nil {
			log.Fatal(e)
		}
		out, e := n.call(parts[0], parts[1], b)
		if e != nil {
			log.Fatal(e)
		}
		os.Stdout.Write(out)
		return
	}
	select {}
}
func parse() config {
	var c config
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	f.StringVar(&c.server, "server", "", "Control-plane base URL")
	f.StringVar(&c.token, "network-token", "", "shared network token")
	f.StringVar(&c.role, "role", "auto", "auto, superpeer or client")
	f.StringVar(&c.nat, "nat-type", "auto", "auto, cone or symmetric")
	f.StringVar(&c.bind, "bind", "0.0.0.0", "UDP bind host")
	f.IntVar(&c.port, "udp-port", 0, "UDP port")
	f.StringVar(&c.endpoint, "public-endpoint", "", "public HOST:PORT")
	f.StringVar(&c.meshIP, "mesh-ip", "", "static mesh IPv4")
	f.StringVar(&c.tun, "tun-name", "", "Linux TUN name")
	f.IntVar(&c.prefix, "mesh-prefix", 24, "mesh prefix")
	f.BoolVar(&c.autoTUN, "tun-auto-configure", false, "configure TUN")
	f.IntVar(&c.capacity, "capacity", 1, "relay capacity")
	f.StringVar(&c.state, "state-dir", "mesh-state", "identity directory")
	f.Var(&c.services, "service", "publish NAME=HOST:PORT")
	f.Var(&c.allows, "allow-node", "allow node ID for services")
	f.BoolVar(&c.noRelay, "no-relay", false, "disable relay")
	f.StringVar(&c.call, "call", "", "NODE_ID:SERVICE to call")
	f.StringVar(&c.requestFile, "request-file", "", "request file")
	f.Parse(os.Args[1:])
	if c.server == "" || c.token == "" {
		f.Usage()
		os.Exit(2)
	}
	if c.role != "auto" && c.role != "client" && c.role != "superpeer" {
		log.Fatal("invalid --role")
	}
	return c
}
func loadIdentity(dir string) (*protocol.Identity, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	p := filepath.Join(dir, "identity.json")
	b, e := os.ReadFile(p)
	if e == nil {
		var x struct {
			Private string `json:"private_key"`
		}
		if e = json.Unmarshal(b, &x); e != nil {
			return nil, e
		}
		raw, e := protocol.B64Decode(x.Private)
		if e != nil {
			return nil, e
		}
		return protocol.ParsePrivateDER(raw)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	i, e := protocol.NewIdentity()
	if e != nil {
		return nil, e
	}
	raw, e := protocol.MarshalPrivateDER(i)
	if e != nil {
		return nil, e
	}
	b, e = json.MarshalIndent(map[string]string{"private_key": protocol.B64Encode(raw)}, "", "  ")
	if e == nil {
		e = os.WriteFile(p, b, 0600)
	}
	return i, e
}
func newNode(c config) (*node, error) {
	id, e := loadIdentity(c.state)
	if e != nil {
		return nil, e
	}
	a, e := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.bind, c.port))
	if e != nil {
		return nil, e
	}
	conn, e := net.ListenUDP("udp4", a)
	if e != nil {
		return nil, e
	}
	k := sha256.Sum256([]byte(c.token))
	n := &node{c: c, id: id, key: k[:], conn: conn, client: &http.Client{Timeout: 10 * time.Second}, dir: map[string]*peer{}, neighbors: map[string]*peer{}, routes: map[string]string{}, seen: map[string]time.Time{}, pending: map[string]chan serviceResult{}, services: map[string]string{}, allow: map[string]bool{"*": true}}
	for _, v := range c.allows {
		if v != "" {
			if len(n.allow) == 1 {
				delete(n.allow, "*")
			}
			n.allow[v] = true
		}
	}
	for _, v := range c.services {
		p := strings.SplitN(v, "=", 2)
		if len(p) != 2 || p[0] == "" {
			return nil, fmt.Errorf("service must be NAME=HOST:PORT")
		}
		if _, _, e := net.SplitHostPort(p[1]); e != nil {
			return nil, fmt.Errorf("invalid service endpoint %q", p[1])
		}
		n.services[p[0]] = p[1]
	}
	return n, nil
}
func (n *node) logf(f string, a ...any) { log.Printf("[%s] %s", n.id.ID[:8], fmt.Sprintf(f, a...)) }
func (n *node) request(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = strings.NewReader(string(b))
	}
	r, e := http.NewRequest(method, strings.TrimRight(n.c.server, "/")+path, body)
	if e != nil {
		return e
	}
	r.Header.Set("X-Mesh-Token", n.c.token)
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	res, e := n.client.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("control plane: %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(res.Body).Decode(out)
}
func (n *node) register() error {
	r := map[string]any{"node_id": n.id.ID, "public_key": n.id.Public, "nat_type": n.c.nat, "role": n.c.role, "relay_capable": !n.c.noRelay, "endpoint": n.c.endpoint, "capacity": n.c.capacity, "mesh_ip": n.c.meshIP}
	var out struct {
		MeshIP string `json:"mesh_ip"`
		Role   string `json:"assigned_role"`
	}
	if e := n.request("POST", "/v1/register", r, &out); e != nil {
		return e
	}
	if out.MeshIP == "" {
		return errors.New("coordinator did not assign mesh_ip")
	}
	n.c.meshIP = out.MeshIP
	n.c.role = out.Role
	n.logf("mesh IP %s; assigned role %s", out.MeshIP, out.Role)
	return nil
}
func (n *node) bootstrap() error {
	var t topology
	if e := n.request("GET", "/v1/bootstrap/"+n.id.ID, nil, &t); e != nil {
		return e
	}
	n.mu.Lock()
	old := n.neighbors
	n.dir = map[string]*peer{}
	for _, v := range t.Directory {
		p := v
		n.dir[p.ID] = &p
	}
	p := t.Self
	n.dir[p.ID] = &p
	n.neighbors = map[string]*peer{}
	for _, v := range t.Neighbors {
		p := v
		if q := old[p.ID]; q != nil {
			p.last = q.last
			p.lastRX = q.lastRX
			p.up = q.up
		}
		n.neighbors[p.ID] = &p
	}
	n.links = t.Links
	n.routes = n.buildRoutes()
	n.mu.Unlock()
	n.logf("topology=%s neighbors=%d", t.Version, len(t.Neighbors))
	return nil
}

type qitem struct {
	id   string
	cost float64
}
type pq []qitem

func (p pq) Len() int           { return len(p) }
func (p pq) Less(i, j int) bool { return p[i].cost < p[j].cost }
func (p pq) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p *pq) Push(x any)        { *p = append(*p, x.(qitem)) }
func (p *pq) Pop() any          { x := (*p)[len(*p)-1]; *p = (*p)[:len(*p)-1]; return x }
func (n *node) buildRoutes() map[string]string {
	adj := map[string][]qitem{}
	for _, e := range n.links {
		adj[e.A] = append(adj[e.A], qitem{e.B, e.Cost})
		adj[e.B] = append(adj[e.B], qitem{e.A, e.Cost})
	}
	cost := map[string]float64{n.id.ID: 0}
	prev := map[string]string{}
	p := &pq{{n.id.ID, 0}}
	heap.Init(p)
	for p.Len() > 0 {
		x := heap.Pop(p).(qitem)
		if cost[x.id] != x.cost {
			continue
		}
		for _, v := range adj[x.id] {
			c := x.cost + v.cost
			if old, ok := cost[v.id]; !ok || c < old {
				cost[v.id] = c
				prev[v.id] = x.id
				heap.Push(p, qitem{v.id, c})
			}
		}
	}
	out := map[string]string{}
	for d := range n.dir {
		if d == n.id.ID {
			continue
		}
		if _, ok := n.neighbors[d]; ok {
			out[d] = d
			continue
		}
		h := d
		for prev[h] != "" && prev[h] != n.id.ID {
			h = prev[h]
		}
		if prev[h] == n.id.ID {
			out[d] = h
		}
	}
	return out
}
func (n *node) start() error {
	if n.c.endpoint == "" {
		endpoint, nat, e := stunEndpoint(n.conn)
		if e != nil {
			return fmt.Errorf("detect external endpoint: %w", e)
		}
		n.c.endpoint = endpoint
		if n.c.nat == "auto" {
			n.c.nat = nat
		}
	}
	if n.c.nat == "auto" {
		n.c.nat = "cone"
	}
	if n.c.role == "superpeer" && n.c.nat != "cone" {
		return errors.New("superpeer requires cone NAT")
	}
	if e := n.register(); e != nil {
		return e
	}
	for name, addr := range n.services {
		host, port, _ := net.SplitHostPort(addr)
		pi, _ := net.LookupPort("tcp", port)
		if e := n.request("POST", "/v1/services", map[string]any{"node_id": n.id.ID, "name": name, "target_host": host, "target_port": pi, "allowed_nodes": strings.Join(n.c.allows, ",")}, &map[string]any{}); e != nil {
			return e
		}
	}
	if e := n.bootstrap(); e != nil {
		return e
	}
	if n.c.tun != "" {
		f, e := openTUN(n.c.tun)
		if e != nil {
			return e
		}
		n.tun = f
		if n.c.autoTUN {
			if e := configureTUN(n.c.tun, n.c.meshIP, n.c.prefix); e != nil {
				return e
			}
			n.logf("TUN %s configured with %s/%d", n.c.tun, n.c.meshIP, n.c.prefix)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	go n.receive(ctx)
	go n.periodic(ctx, keepAlive, n.helloAll)
	go n.periodic(ctx, refresh, func() {
		if e := n.bootstrap(); e != nil {
			n.logf("topology refresh failed: %v", e)
		}
	})
	go n.periodic(ctx, heartbeat, func() {
		if e := n.register(); e != nil {
			n.logf("heartbeat failed: %v", e)
		}
	})
	if n.tun != nil {
		go n.tunLoop(ctx)
	}
	n.helloAll()
	n.logf("listening on %s", n.conn.LocalAddr())
	return nil
}
func (n *node) periodic(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}
func (n *node) helloAll() {
	n.mu.RLock()
	a := make([]string, 0, len(n.neighbors))
	for id := range n.neighbors {
		a = append(a, id)
	}
	n.mu.RUnlock()
	for _, id := range a {
		n.send(protocol.NewPacket("HELLO", n.id.ID, id, map[string]any{"public_key": n.id.Public}))
	}
}
func (n *node) usable(p *peer) bool {
	return p != nil && (p.lastRX.IsZero() || time.Since(p.lastRX) < linkTimeout)
}
func (n *node) send(p protocol.Packet) bool {
	n.mu.RLock()
	hop := n.routes[p.Destination]
	q := n.neighbors[hop]
	n.mu.RUnlock()
	if !n.usable(q) {
		return false
	}
	a := q.last
	if a == nil {
		var e error
		a, e = net.ResolveUDPAddr("udp", q.Endpoint)
		if e != nil {
			return false
		}
	}
	b, e := protocol.EncodePacket(p, n.key)
	if e != nil {
		return false
	}
	_, e = n.conn.WriteToUDP(b, a.(*net.UDPAddr))
	return e == nil
}
func (n *node) receive(ctx context.Context) {
	b := make([]byte, 65535)
	for {
		n.conn.SetReadDeadline(time.Now().Add(time.Second))
		l, a, e := n.conn.ReadFromUDP(b)
		if e != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		d := append([]byte(nil), b[:l]...)
		if strings.HasPrefix(string(d), fastMagic) {
			n.fast(d, a)
			continue
		}
		p, e := protocol.DecodePacket(d, n.key)
		if e != nil || !n.remember(p.ID) {
			continue
		}
		n.touch(p.Source, a)
		if p.Destination != n.id.ID {
			if n.c.role == "superpeer" {
				if q, e := p.DecTTL(); e == nil {
					n.send(q)
				}
			}
			continue
		}
		switch p.Type {
		case "HELLO":
			n.send(protocol.NewPacket("HELLO_ACK", n.id.ID, p.Source, map[string]any{}))
		case "DATA":
			n.data(p)
		}
	}
}
func (n *node) remember(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seen[id]; ok {
		return false
	}
	n.seen[id] = time.Now()
	if len(n.seen) > 10000 {
		for k := range n.seen {
			delete(n.seen, k)
			break
		}
	}
	return true
}
func (n *node) touch(id string, a net.Addr) {
	n.mu.Lock()
	if p := n.neighbors[id]; p != nil {
		p.last = a
		p.lastRX = time.Now()
		p.up = true
	}
	n.mu.Unlock()
}
func (n *node) peerKey(id string) ([]byte, *peer, error) {
	n.mu.RLock()
	p := n.dir[id]
	n.mu.RUnlock()
	if p == nil {
		return nil, nil, errors.New("unknown peer")
	}
	k, e := protocol.SharedKey(n.id.Private, p.Public)
	return k, p, e
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
	}
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
	select {
	case x := <-ch:
		if x.Error != "" {
			return nil, errors.New(x.Error)
		}
		return protocol.B64Decode(x.Data)
	case <-time.After(30 * time.Second):
		return nil, errors.New("service response timed out")
	}
}
func (n *node) close() {
	if n.stop != nil {
		n.stop()
	}
	n.conn.Close()
	if n.tun != nil {
		n.tun.Close()
	}
}

// Compact fast IPv4 frame: MIP1 | ttl | source node ID | destination node ID | packet ID | sealed fragment | HMAC.
func (n *node) fast(data []byte, a *net.UDPAddr) {
	if len(data) < fastHeader+28+fastMAC {
		return
	}
	auth, mac := data[:len(data)-fastMAC], data[len(data)-fastMAC:]
	h := hmac.New(sha256.New, n.key)
	h.Write(auth)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return
	}
	ttl := int(auth[4])
	src := hex.EncodeToString(auth[5:21])
	dst := hex.EncodeToString(auth[21:37])
	pid := hex.EncodeToString(auth[37:49])
	if ttl < 1 || ttl > protocol.DefaultTTL || !n.remember(pid) {
		return
	}
	n.touch(src, a)
	if dst != n.id.ID {
		if n.c.role == "superpeer" && ttl > 1 {
			auth = append([]byte(nil), auth...)
			auth[4]--
			h := hmac.New(sha256.New, n.key)
			h.Write(auth)
			n.sendFast(dst, append(auth, h.Sum(nil)...))
		}
		return
	}
	k, _, e := n.peerKey(src)
	if e != nil {
		return
	}
	plain, e := protocol.OpenBytes(k, auth[fastHeader:], []byte(src+":"+dst))
	if e != nil || len(plain) < 12 {
		return
	}
	n.deliver(src, plain[12:])
}
func (n *node) sendFast(dst, data []byte) bool {
	n.mu.RLock()
	p := n.neighbors[n.routes[dst]]
	n.mu.RUnlock()
	if !n.usable(p) {
		return false
	}
	a := p.last
	if a == nil {
		var e error
		a, e = net.ResolveUDPAddr("udp", p.Endpoint)
		if e != nil {
			return false
		}
	}
	_, e := n.conn.WriteToUDP(data, a.(*net.UDPAddr))
	return e == nil
}
func (n *node) tunLoop(ctx context.Context) {
	b := make([]byte, maxTUN+1)
	for {
		l, e := n.tun.Read(b)
		if e != nil || ctx.Err() != nil {
			return
		}
		if l < 20 || b[0]>>4 != 4 || l > maxTUN {
			continue
		}
		src := netip.AddrFrom4([4]byte(b[12:16])).String()
		dstIP := netip.AddrFrom4([4]byte(b[16:20])).String()
		if src != n.c.meshIP {
			continue
		}
		n.mu.RLock()
		var dst string
		for id, p := range n.dir {
			if p.MeshIP == dstIP {
				dst = id
			}
		}
		n.mu.RUnlock()
		if dst == "" {
			continue
		}
		n.sendIP(dst, b[:l])
	}
}
func (n *node) sendIP(dst string, p []byte) {
	k, _, e := n.peerKey(dst)
	if e != nil {
		return
	}
	fragmentID := make([]byte, 8)
	packetID := make([]byte, 12)
	if _, e = rand.Read(fragmentID); e != nil {
		return
	}
	if _, e = rand.Read(packetID); e != nil {
		return
	}
	plain := make([]byte, 12+len(p))
	copy(plain, fragmentID)
	binary.BigEndian.PutUint16(plain[8:], 0)
	binary.BigEndian.PutUint16(plain[10:], 1)
	copy(plain[12:], p)
	sealed, e := protocol.SealBytes(k, plain, []byte(n.id.ID+":"+dst))
	if e != nil {
		return
	}
	src, _ := hex.DecodeString(n.id.ID)
	target, _ := hex.DecodeString(dst)
	pkt := make([]byte, fastHeader)
	copy(pkt, fastMagic)
	pkt[4] = protocol.DefaultTTL
	copy(pkt[5:], src)
	copy(pkt[21:], target)
	copy(pkt[37:], packetID)
	pkt = append(pkt, sealed...)
	h := hmac.New(sha256.New, n.key)
	h.Write(pkt)
	n.sendFast(dst, append(pkt, h.Sum(nil)...))
}
func (n *node) deliver(src string, p []byte) {
	if n.tun == nil || len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	n.mu.RLock()
	expected := ""
	if q := n.dir[src]; q != nil {
		expected = q.MeshIP
	}
	n.mu.RUnlock()
	if netip.AddrFrom4([4]byte(p[12:16])).String() != expected || netip.AddrFrom4([4]byte(p[16:20])).String() != n.c.meshIP {
		return
	}
	n.tun.Write(p)
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func stunEndpoint(c *net.UDPConn) (string, string, error) {
	servers := []string{"stun.nextcloud.com:3478", "stun.miwifi.com:3478", "stun.sipgate.net:3478"}
	var mapped []string
	for _, server := range servers {
		a, e := net.ResolveUDPAddr("udp", server)
		if e != nil {
			continue
		}
		var tx [12]byte
		rand.Read(tx[:])
		req := make([]byte, 20)
		binary.BigEndian.PutUint16(req, 1)
		binary.BigEndian.PutUint32(req[4:], 0x2112A442)
		copy(req[8:], tx[:])
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, e = c.WriteToUDP(req, a); e != nil {
			continue
		}
		b := make([]byte, 2048)
		l, _, e := c.ReadFromUDP(b)
		if e != nil || l < 20 || string(b[8:20]) != string(tx[:]) {
			continue
		}
		for p := 20; p+4 <= l; {
			typ, size := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
			v := b[p+4 : min(p+4+size, l)]
			if typ == 0x0020 && len(v) >= 8 && v[1] == 1 {
				port := binary.BigEndian.Uint16(v[2:4]) ^ 0x2112
				ip := binary.BigEndian.Uint32(v[4:8]) ^ 0x2112A442
				mapped = append(mapped, fmt.Sprintf("%d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port))
				break
			}
			p += 4 + (size+3)&^3
		}
		if len(mapped) == 2 {
			if mapped[0] == mapped[1] {
				return mapped[0], "cone", nil
			}
			return mapped[0], "symmetric", nil
		}
	}
	if len(mapped) > 0 {
		return mapped[0], "cone", nil
	}
	return "", "", errors.New("no STUN server responded")
}
