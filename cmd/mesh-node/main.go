// Command mesh-node runs an encrypted UDP overlay endpoint and optional service gateway.
package main

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/cipher"
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
	_ "net/http/pprof"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"home-udp-mesh/internal/protocol"
)

const (
	keepAlive   = 10 * time.Second
	refresh     = 5 * time.Second
	heartbeat   = 15 * time.Second
	linkTimeout = 30 * time.Second
	linkGrace   = 35 * time.Second
	maxRequest  = 32000
	maxResponse = 48000

	symmetricBurstSize    = 500
	symmetricBurstTimeout = 45 * time.Second
	scanInitialStart      = -1000
	scanInitialEnd        = 2000
	scanExpand            = 2000
	scanDelay             = 500 * time.Microsecond
	fastMagic             = "MIP1"
	fastMAC               = 32
	fastHeader            = 49
	maxTUN                = 1279
	fastBatchSize         = 32
	fastQueueSize         = 1024
	maxFastFrame          = fastHeader + 12 + 12 + maxTUN + 16 + fastMAC
)

var fastMagicBytes = []byte(fastMagic)

type config struct {
	server, token, role, nat, bind, endpoint, meshIP, tun, state, call, requestFile, pprofListen string
	port, capacity, prefix                                                                       int
	noRelay, autoTUN, debug                                                                      bool
	fastWorkers                                                                                  int
	statsInterval                                                                                time.Duration
	services, allows                                                                             multi
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
type cachedKey struct {
	public  string
	key     []byte
	aead    cipher.AEAD
	nonces  *protocol.NonceSequence
	openAAD []byte
	sealAAD []byte
}
type reassembly struct {
	count      uint16
	chunks     map[uint16][]byte
	receivedAt time.Time
}
type symmetricReply struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}
type fastFrame struct {
	data []byte
	addr *net.UDPAddr
}
type fastStats struct {
	receivedPackets, receivedBytes   atomic.Uint64
	queueDrops                       atomic.Uint64
	sentPackets, sentBytes           atomic.Uint64
	deliveredPackets, deliveredBytes atomic.Uint64
}
type node struct {
	c         config
	id        *protocol.Identity
	key       []byte
	conn      *net.UDPConn
	packet    *ipv4.PacketConn
	client    *http.Client
	mu        sync.RWMutex
	dir       map[string]*peer
	neighbors map[string]*peer
	links     []edge
	routes    map[string]string
	meshNodes map[netip.Addr]string
	seen      map[string]time.Time
	pending   map[string]chan serviceResult
	services  map[string]string
	allow     map[string]bool
	stop      context.CancelFunc
	tun       *os.File
	startedAt time.Time
	fastQueue chan fastFrame
	fastPool  sync.Pool
	stats     fastStats

	sharedKeys map[string]cachedKey
	reassembly map[string]*reassembly

	symmetricMu        sync.Mutex
	symmetricReady     bool
	symmetricScans     map[string]chan struct{}
	symmetricConnected map[string]bool
	symmetricBurstAt   map[string]time.Time
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
	f.BoolVar(&c.debug, "debug", false, "log data-plane packet decisions")
	f.IntVar(&c.fastWorkers, "fast-workers", 0, "fast packet workers (0 = CPU count, max 16)")
	f.DurationVar(&c.statsInterval, "stats-interval", 0, "log fast-path throughput and queue statistics (0 = off)")
	f.StringVar(&c.pprofListen, "pprof-listen", "", "local pprof listener, e.g. 127.0.0.1:6060")
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
	if c.statsInterval < 0 {
		log.Fatal("--stats-interval must not be negative")
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
	n := &node{
		c:                  c,
		id:                 id,
		key:                k[:],
		conn:               conn,
		packet:             ipv4.NewPacketConn(conn),
		client:             &http.Client{Timeout: 10 * time.Second},
		dir:                map[string]*peer{},
		neighbors:          map[string]*peer{},
		routes:             map[string]string{},
		meshNodes:          map[netip.Addr]string{},
		seen:               map[string]time.Time{},
		pending:            map[string]chan serviceResult{},
		services:           map[string]string{},
		allow:              map[string]bool{"*": true},
		startedAt:          time.Now(),
		sharedKeys:         map[string]cachedKey{},
		reassembly:         map[string]*reassembly{},
		symmetricScans:     map[string]chan struct{}{},
		symmetricConnected: map[string]bool{},
		symmetricBurstAt:   map[string]time.Time{},
	}
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
func (n *node) debugf(f string, a ...any) {
	if n.c.debug {
		n.logf(f, a...)
	}
}
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
	n.meshNodes = map[netip.Addr]string{}
	for _, v := range t.Directory {
		p := v
		n.dir[p.ID] = &p
		if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
			n.meshNodes[ip] = p.ID
		}
	}
	p := t.Self
	n.dir[p.ID] = &p
	if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
		n.meshNodes[ip] = p.ID
	}
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
	if n.c.role == "superpeer" {
		for _, candidate := range t.Neighbors {
			if candidate.NAT == "symmetric" {
				n.startSymmetricScan(candidate.ID, candidate.Endpoint, false)
			}
		}
	}
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
	if !n.establishSymmetricTransport() {
		return errors.New("symmetric NAT synchronization with a superpeer failed")
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
	if e := n.startPprof(); e != nil {
		return e
	}
	n.startFastWorkers(ctx)
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
	go n.linkHealth(ctx)
	if n.c.statsInterval > 0 {
		go n.statsLoop(ctx, n.c.statsInterval)
	}
	if n.tun != nil {
		go n.tunLoop(ctx)
	}
	n.helloAll()
	n.logf("listening on %s", n.conn.LocalAddr())
	return nil
}

// establishSymmetricTransport mirrors the legacy 500-port burst.  A symmetric
// NAT allocates a mapping per destination, therefore one of these sockets must
// receive the cone superpeer's HELLO before it becomes the node's transport.
func (n *node) establishSymmetricTransport() bool {
	if n.c.nat != "symmetric" {
		return true
	}
	n.symmetricMu.Lock()
	if n.symmetricReady {
		n.symmetricMu.Unlock()
		return true
	}
	n.symmetricMu.Unlock()

	n.mu.RLock()
	var relay *peer
	var relayID string
	for id, candidate := range n.neighbors {
		if candidate.Role == "superpeer" {
			relayID, relay = id, candidate
			break
		}
	}
	n.mu.RUnlock()
	if relay == nil {
		n.logf("symmetric burst deferred: no superpeer in topology")
		return false
	}
	endpoint, err := net.ResolveUDPAddr("udp", relay.Endpoint)
	if err != nil {
		n.logf("invalid superpeer endpoint: %v", err)
		return false
	}

	responses := make(chan symmetricReply, symmetricBurstSize)
	sockets := make([]*net.UDPConn, 0, symmetricBurstSize)
	n.logf("symmetric NAT: probing %d UDP ports via %s", symmetricBurstSize, relayID[:8])
	for range symmetricBurstSize {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(n.c.bind)})
		if err != nil {
			continue
		}
		burst := protocol.NewPacket("SYMMETRIC_BURST", n.id.ID, relayID, map[string]any{})
		encoded, err := protocol.EncodePacket(burst, n.key)
		if err != nil {
			probe.Close()
			continue
		}
		if _, err = probe.WriteToUDP(encoded, endpoint); err != nil {
			probe.Close()
			continue
		}
		sockets = append(sockets, probe)
		go n.awaitSymmetricHello(probe, relayID, responses)
	}

	deadline := time.NewTimer(symmetricBurstTimeout)
	defer deadline.Stop()
	var selected *net.UDPConn
	for selected == nil {
		select {
		case received := <-responses:
			selected = received.conn
			ack := protocol.NewPacket("HELLO_ACK", n.id.ID, relayID, map[string]any{})
			if encoded, err := protocol.EncodePacket(ack, n.key); err == nil {
				_, _ = selected.WriteToUDP(encoded, received.addr)
			}
		case <-deadline.C:
			for _, probe := range sockets {
				_ = probe.Close()
			}
			n.logf("symmetric NAT burst timed out without HELLO")
			return false
		}
	}
	for _, probe := range sockets {
		if probe != selected {
			_ = probe.Close()
		}
	}
	old := n.conn
	n.conn = selected
	_ = old.Close()
	n.symmetricMu.Lock()
	n.symmetricReady = true
	n.symmetricMu.Unlock()
	n.logf("symmetric NAT synchronized through %s on %s", relayID[:8], selected.LocalAddr())
	return true
}

func (n *node) awaitSymmetricHello(conn *net.UDPConn, relayID string, responses chan<- symmetricReply) {
	_ = conn.SetReadDeadline(time.Now().Add(symmetricBurstTimeout))
	buffer := make([]byte, 65535)
	length, address, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return
	}
	packet, err := protocol.DecodePacket(buffer[:length], n.key)
	if err != nil || packet.Type != "HELLO" || packet.Source != relayID || packet.Destination != n.id.ID {
		return
	}
	select {
	case responses <- symmetricReply{conn: conn, addr: address}:
	default:
	}
}

func (n *node) startSymmetricScan(peerID, endpoint string, force bool) {
	n.symmetricMu.Lock()
	if existing := n.symmetricScans[peerID]; existing != nil {
		if !force {
			n.symmetricMu.Unlock()
			return
		}
		delete(n.symmetricScans, peerID)
		close(existing)
	}
	if n.symmetricConnected[peerID] && !force {
		n.symmetricMu.Unlock()
		return
	}
	cancel := make(chan struct{})
	n.symmetricScans[peerID] = cancel
	n.symmetricMu.Unlock()
	go n.scanSymmetricNeighbor(peerID, endpoint, cancel)
}

func (n *node) scanSymmetricNeighbor(peerID, endpoint string, cancel chan struct{}) {
	defer func() {
		n.symmetricMu.Lock()
		if n.symmetricScans[peerID] == cancel {
			delete(n.symmetricScans, peerID)
		}
		n.symmetricMu.Unlock()
	}()
	address, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		n.logf("symmetric scan endpoint for %s: %v", peerID[:8], err)
		return
	}
	n.logf("symmetric scan for %s around %s", peerID[:8], endpoint)
	scanned := make(map[int]bool)
	for startOffset, endOffset := scanInitialStart, scanInitialEnd; ; startOffset, endOffset = startOffset-scanExpand, endOffset+scanExpand {
		start, end := max(1, address.Port+startOffset), min(65535, address.Port+endOffset)
		for port := start; port <= end; port++ {
			select {
			case <-cancel:
				n.symmetricMu.Lock()
				n.symmetricConnected[peerID] = true
				n.symmetricMu.Unlock()
				n.logf("symmetric scan connected to %s", peerID[:8])
				return
			default:
			}
			if scanned[port] {
				continue
			}
			scanned[port] = true
			target := *address
			target.Port = port
			n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, peerID, map[string]any{"public_key": n.id.Public}), &target)
			time.Sleep(scanDelay)
		}
		if start == 1 && end == 65535 {
			break
		}
	}
	n.logf("symmetric scan exhausted UDP ports for %s", peerID[:8])
}

func (n *node) completeSymmetricScan(peerID string) {
	n.symmetricMu.Lock()
	cancel := n.symmetricScans[peerID]
	if cancel != nil {
		delete(n.symmetricScans, peerID)
		close(cancel)
	}
	n.symmetricMu.Unlock()
}

func (n *node) handleSymmetricBurst(packet protocol.Packet) {
	if n.c.role != "superpeer" {
		return
	}
	n.mu.RLock()
	peer := n.neighbors[packet.Source]
	n.mu.RUnlock()
	if peer == nil || peer.NAT != "symmetric" {
		return
	}
	n.symmetricMu.Lock()
	previous := n.symmetricBurstAt[packet.Source]
	n.symmetricBurstAt[packet.Source] = time.Now()
	n.symmetricMu.Unlock()
	if time.Since(previous) < 5*time.Second {
		return
	}
	n.startSymmetricScan(packet.Source, peer.Endpoint, true)
}

func (n *node) sendToAddress(packet protocol.Packet, address *net.UDPAddr) {
	encoded, err := protocol.EncodePacket(packet, n.key)
	if err != nil {
		return
	}
	_, _ = n.conn.WriteToUDP(encoded, address)
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
	_, q := n.nextHop(p.Destination)
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

func (n *node) nextHop(destination string) (string, *peer) {
	n.mu.RLock()
	hop := n.routes[destination]
	peer := n.neighbors[hop]
	if n.usable(peer) {
		n.mu.RUnlock()
		return hop, peer
	}

	adjacency := map[string][]qitem{}
	for _, edge := range n.links {
		adjacency[edge.A] = append(adjacency[edge.A], qitem{edge.B, edge.Cost})
		adjacency[edge.B] = append(adjacency[edge.B], qitem{edge.A, edge.Cost})
	}
	costs := map[string]float64{n.id.ID: 0}
	previous := map[string]string{}
	queue := &pq{{n.id.ID, 0}}
	heap.Init(queue)
	for queue.Len() > 0 {
		current := heap.Pop(queue).(qitem)
		if current.cost != costs[current.id] {
			continue
		}
		for _, candidate := range adjacency[current.id] {
			if current.id == n.id.ID && !n.usable(n.neighbors[candidate.id]) {
				continue
			}
			candidateCost := current.cost + candidate.cost
			if existing, ok := costs[candidate.id]; !ok || candidateCost < existing {
				costs[candidate.id] = candidateCost
				previous[candidate.id] = current.id
				heap.Push(queue, qitem{candidate.id, candidateCost})
			}
		}
	}
	if _, ok := previous[destination]; !ok {
		n.mu.RUnlock()
		return "", nil
	}
	hop = destination
	for previous[hop] != n.id.ID {
		parent := previous[hop]
		if parent == "" {
			n.mu.RUnlock()
			return "", nil
		}
		hop = parent
	}
	peer = n.neighbors[hop]
	n.mu.RUnlock()
	if !n.usable(peer) {
		return "", nil
	}
	n.mu.Lock()
	n.routes[destination] = hop
	n.mu.Unlock()
	n.logf("route failover %s -> %s", destination[:8], hop[:8])
	return hop, peer
}
func (n *node) startFastWorkers(ctx context.Context) {
	workers := n.c.fastWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	workers = min(workers, 16)
	n.fastQueue = make(chan fastFrame, fastQueueSize)
	n.fastPool.New = func() any { return make([]byte, maxFastFrame) }
	for range workers {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case frame, ok := <-n.fastQueue:
					if !ok {
						return
					}
					n.fast(frame.data, frame.addr)
					n.fastPool.Put(frame.data[:maxFastFrame])
				}
			}
		}()
	}
}

func (n *node) startPprof() error {
	if n.c.pprofListen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(n.c.pprofListen)
	if err != nil {
		return fmt.Errorf("invalid --pprof-listen: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("--pprof-listen must use localhost or a loopback IP")
	}
	go func() {
		n.logf("pprof available at http://%s/debug/pprof/", n.c.pprofListen)
		if err := http.ListenAndServe(n.c.pprofListen, nil); err != nil {
			n.logf("pprof listener stopped: %v", err)
		}
	}()
	return nil
}

func (n *node) statsLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var previous fastStatsSnapshot
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := n.fastStatsSnapshot()
			rxPackets := current.receivedPackets - previous.receivedPackets
			rxBytes := current.receivedBytes - previous.receivedBytes
			txPackets := current.sentPackets - previous.sentPackets
			txBytes := current.sentBytes - previous.sentBytes
			drops := current.queueDrops - previous.queueDrops
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			n.logf("fast stats %s: rx=%d pps %.2f Mbps tx=%d pps %.2f Mbps tun=%d pps queue=%d/%d drops=%d heap=%.1f MiB goroutines=%d",
				interval, rxPackets, float64(rxBytes*8)/interval.Seconds()/1e6,
				txPackets, float64(txBytes*8)/interval.Seconds()/1e6,
				current.deliveredPackets-previous.deliveredPackets, len(n.fastQueue), cap(n.fastQueue), drops,
				float64(mem.HeapAlloc)/(1024*1024), runtime.NumGoroutine())
			previous = current
		}
	}
}

type fastStatsSnapshot struct {
	receivedPackets, receivedBytes   uint64
	queueDrops                       uint64
	sentPackets, sentBytes           uint64
	deliveredPackets, deliveredBytes uint64
}

func (n *node) fastStatsSnapshot() fastStatsSnapshot {
	return fastStatsSnapshot{
		receivedPackets: n.stats.receivedPackets.Load(), receivedBytes: n.stats.receivedBytes.Load(),
		queueDrops: n.stats.queueDrops.Load(), sentPackets: n.stats.sentPackets.Load(), sentBytes: n.stats.sentBytes.Load(),
		deliveredPackets: n.stats.deliveredPackets.Load(), deliveredBytes: n.stats.deliveredBytes.Load(),
	}
}

func (n *node) enqueueFast(data []byte, addr *net.UDPAddr) {
	n.stats.receivedPackets.Add(1)
	n.stats.receivedBytes.Add(uint64(len(data)))
	if len(data) > maxFastFrame {
		n.debugf("drop fast frame from %s: exceeds MTU (%d bytes)", addr, len(data))
		return
	}
	// ReadBatch reuses its buffers after this call. Copy only fast packets into
	// a bounded pool so workers can decrypt in parallel without retaining the
	// 60 KiB control-plane receive buffers.
	owned := n.fastPool.Get().([]byte)[:len(data)]
	copy(owned, data)
	select {
	case n.fastQueue <- fastFrame{data: owned, addr: addr}:
	default:
		// UDP has no backpressure. A bounded queue makes overload a visible
		// packet drop instead of an unbounded allocation or stalled receiver.
		n.fastPool.Put(owned[:maxFastFrame])
		n.stats.queueDrops.Add(1)
		n.debugf("drop fast frame from %s: worker queue full", addr)
	}
}

func (n *node) receive(ctx context.Context) {
	messages := make([]ipv4.Message, fastBatchSize)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, protocol.MaxDatagramSize)}
	}
	defer close(n.fastQueue)
	for {
		n.packet.SetReadDeadline(time.Now().Add(time.Second))
		count, e := n.packet.ReadBatch(messages, 0)
		if e != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}
		for _, message := range messages[:count] {
			datagram := message.Buffers[0][:message.N]
			a, ok := message.Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			if len(datagram) >= len(fastMagicBytes) && bytes.Equal(datagram[:len(fastMagicBytes)], fastMagicBytes) {
				n.enqueueFast(datagram, a)
				continue
			}
			p, e := protocol.DecodePacket(datagram, n.key)
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
				n.ensureNeighbor(p.Source)
				n.send(protocol.NewPacket("HELLO_ACK", n.id.ID, p.Source, map[string]any{}))
			case "HELLO_ACK":
				n.completeSymmetricScan(p.Source)
			case "SYMMETRIC_BURST":
				n.ensureNeighbor(p.Source)
				n.handleSymmetricBurst(p)
			case "DATA":
				n.ensureNeighbor(p.Source)
				n.data(p)
			}
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

func (n *node) ensureNeighbor(id string) {
	n.mu.RLock()
	known := n.neighbors[id] != nil
	n.mu.RUnlock()
	if known {
		return
	}
	n.logf("received traffic from new node %s; refreshing topology", id[:8])
	if err := n.bootstrap(); err != nil {
		n.logf("topology refresh failed: %v", err)
	}
}

func (n *node) linkHealth(ctx context.Context) {
	ticker := time.NewTicker(keepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.mu.Lock()
			for id, peer := range n.neighbors {
				live := n.usable(peer)
				if peer.up != live {
					peer.up = live
					state := "down"
					if live {
						state = "up"
					}
					n.logf("link %s %s", id[:8], state)
				}
			}
			n.mu.Unlock()
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
		aead, cipherErr := protocol.NewAEAD(k)
		if cipherErr != nil {
			return nil, nil, cipherErr
		}
		nonces, nonceErr := protocol.NewNonceSequence()
		if nonceErr != nil {
			return nil, nil, nonceErr
		}
		n.mu.Lock()
		n.sharedKeys[id] = cachedKey{public: p.Public, key: k, aead: aead, nonces: nonces, openAAD: []byte(id + ":" + n.id.ID), sealAAD: []byte(n.id.ID + ":" + id)}
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

func (n *node) peerCipher(id string) (cipher.AEAD, *protocol.NonceSequence, []byte, error) {
	if _, _, err := n.peerKey(id); err != nil {
		return nil, nil, nil, err
	}
	n.mu.RLock()
	cached, ok := n.sharedKeys[id]
	n.mu.RUnlock()
	if !ok || cached.aead == nil || cached.nonces == nil {
		return nil, nil, nil, errors.New("missing peer cipher")
	}
	return cached.aead, cached.nonces, cached.sealAAD, nil
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
	case "IP_PACKET":
		encoded, _ := m.Body["data"].(string)
		if payload, err := protocol.B64Decode(encoded); err == nil {
			n.deliver(p.Source, payload)
		}
	}
}

// handleLegacyIPFragment accepts the JSON-sealed fragment representation used
// before the compact MIP1 data plane.  Keeping it makes rolling upgrades safe:
// a Go destination can receive packets from an older mesh node.
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
	if len(plain) < 12 {
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
	cutoff := time.Now().Add(-10 * time.Second)
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
	state.chunks[index] = append([]byte(nil), plain[12:]...)
	state.receivedAt = time.Now()
	if len(state.chunks) != int(count) {
		return
	}
	packet := make([]byte, 0)
	for part := uint16(0); part < count; part++ {
		chunk, ok := state.chunks[part]
		if !ok {
			return
		}
		packet = append(packet, chunk...)
	}
	delete(n.reassembly, stateID)
	go n.deliver(source, packet)
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
		n.debugf("drop fast frame from %s: truncated (%d bytes)", a, len(data))
		return
	}
	auth, mac := data[:len(data)-fastMAC], data[len(data)-fastMAC:]
	h := hmac.New(sha256.New, n.key)
	h.Write(auth)
	var expectedMAC [fastMAC]byte
	if !hmac.Equal(mac, h.Sum(expectedMAC[:0])) {
		n.debugf("drop fast frame from %s: HMAC failed", a)
		return
	}
	ttl := int(auth[4])
	src := hex.EncodeToString(auth[5:21])
	dst := hex.EncodeToString(auth[21:37])
	pid := hex.EncodeToString(auth[37:49])
	if ttl < 1 || ttl > protocol.DefaultTTL || !n.remember(pid) {
		n.debugf("drop fast frame %s->%s: invalid TTL or duplicate", src[:8], dst[:8])
		return
	}
	n.touch(src, a)
	if dst != n.id.ID {
		if n.c.role == "superpeer" && ttl > 1 {
			// Reserve space for the new MAC while copying: the old frame's
			// backing array belongs to the UDP read buffer and cannot be reused.
			auth = append(make([]byte, 0, len(auth)+fastMAC), auth...)
			auth[4]--
			h := hmac.New(sha256.New, n.key)
			h.Write(auth)
			n.sendFast(dst, h.Sum(auth))
		}
		return
	}
	aead, aad, e := n.peerAEAD(src)
	if e != nil {
		n.debugf("drop fast frame from %s: %v", src[:8], e)
		return
	}
	plain, e := protocol.OpenBytesWithAEAD(aead, auth[fastHeader:], aad)
	if e != nil {
		n.debugf("drop fast frame %s->%s: decrypt failed: %v", src[:8], dst[:8], e)
		return
	}
	n.debugf("fast frame %s->%s received (%d bytes encrypted)", src[:8], dst[:8], len(data))
	n.acceptIPFragment(src, plain)
}
func (n *node) sendFast(dst string, data []byte) bool {
	_, p := n.nextHop(dst)
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
	_, e := n.conn.WriteToUDP(data, a.(*net.UDPAddr))
	if e != nil {
		n.debugf("fast send to %s via %s failed: %v", dst[:8], a, e)
		return false
	}
	n.stats.sentPackets.Add(1)
	n.stats.sentBytes.Add(uint64(len(data)))
	n.debugf("fast frame sent to %s via %s (%d bytes)", dst[:8], a, len(data))
	return true
}
func (n *node) tunLoop(ctx context.Context) {
	n.logf("TUN reader started")
	b := make([]byte, maxTUN+1)
	for {
		l, e := readTUN(n.tun, b)
		if e != nil {
			if ctx.Err() == nil {
				n.logf("TUN read failed: %v", e)
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		if l < 20 || b[0]>>4 != 4 || l > maxTUN {
			n.debugf("drop TUN frame: invalid IPv4 or exceeds MTU (%d bytes)", l)
			continue
		}
		src := netip.AddrFrom4([4]byte(b[12:16])).String()
		dstIP := netip.AddrFrom4([4]byte(b[16:20])).String()
		if src != n.c.meshIP {
			n.debugf("drop TUN frame: source %s is not local mesh IP", src)
			continue
		}
		n.mu.RLock()
		dst := n.meshNodes[netip.AddrFrom4([4]byte(b[16:20]))]
		n.mu.RUnlock()
		if dst == "" {
			n.debugf("drop TUN frame: no node owns %s", dstIP)
			continue
		}
		n.debugf("TUN IPv4 %s -> %s (%d bytes)", src, dstIP, l)
		if !n.sendIP(dst, b[:l]) {
			n.debugf("TUN IPv4 %s -> %s: send failed", src, dstIP)
		}
	}
}
func (n *node) sendIP(dst string, p []byte) bool {
	aead, nonces, aad, e := n.peerCipher(dst)
	if e != nil {
		n.debugf("IP send to %s: %v", dst[:8], e)
		return false
	}
	fragmentID := make([]byte, 8)
	packetID := make([]byte, 12)
	if _, e = rand.Read(fragmentID); e != nil {
		return false
	}
	if _, e = rand.Read(packetID); e != nil {
		return false
	}
	plain := make([]byte, 12+len(p))
	copy(plain, fragmentID)
	binary.BigEndian.PutUint16(plain[8:], 0)
	binary.BigEndian.PutUint16(plain[10:], 1)
	copy(plain[12:], p)
	sealed, e := protocol.SealBytesWithSequence(aead, nonces, plain, aad)
	if e != nil {
		return false
	}
	src, _ := hex.DecodeString(n.id.ID)
	target, _ := hex.DecodeString(dst)
	pkt := make([]byte, fastHeader, fastHeader+len(sealed)+fastMAC)
	copy(pkt, fastMagic)
	pkt[4] = protocol.DefaultTTL
	copy(pkt[5:], src)
	copy(pkt[21:], target)
	copy(pkt[37:], packetID)
	pkt = append(pkt, sealed...)
	h := hmac.New(sha256.New, n.key)
	h.Write(pkt)
	return n.sendFast(dst, h.Sum(pkt))
}
func (n *node) deliver(src string, p []byte) {
	if n.tun == nil || len(p) < 20 || len(p) > maxTUN || p[0]>>4 != 4 {
		n.debugf("drop IP packet from %s: invalid packet or TUN disabled", src[:8])
		return
	}
	n.mu.RLock()
	expected := ""
	if q := n.dir[src]; q != nil {
		expected = q.MeshIP
	}
	n.mu.RUnlock()
	if netip.AddrFrom4([4]byte(p[12:16])).String() != expected || netip.AddrFrom4([4]byte(p[16:20])).String() != n.c.meshIP {
		n.debugf("drop IP packet from %s: address ownership check failed", src[:8])
		return
	}
	if _, err := n.tun.Write(p); err != nil {
		n.debugf("deliver IP packet from %s failed: %v", src[:8], err)
		return
	}
	n.stats.deliveredPackets.Add(1)
	n.stats.deliveredBytes.Add(uint64(len(p)))
	n.debugf("TUN IPv4 delivered from %s (%d bytes)", src[:8], len(p))
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
