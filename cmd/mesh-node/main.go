// Command mesh-node runs an encrypted UDP overlay endpoint and optional service gateway.
package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
	"home-udp-mesh/internal/autostart"
	"home-udp-mesh/internal/protocol"
)

const (
	// PING/PONG maintains liveness and learns a peer's current UDP endpoint.
	// HELLO carries a public key and therefore only needs a slow background
	// refresh after the immediate startup and topology-change handshakes.
	pingInterval       = 15 * time.Second
	helloInterval      = 90 * time.Second
	linkHealthInterval = 5 * time.Second
	refresh            = 5 * time.Second
	heartbeat          = 20 * time.Second
	telemetryInterval  = 15 * time.Second
	recoveryCheck      = 5 * time.Second
	topologyPoll       = 90 * time.Second
	linkTimeout        = 30 * time.Second
	// Upper bound for one blocking UDP receive. The receive loop renews the
	// deadline each iteration; the brief unlock between reads lets rebind or
	// STUN take the exclusive udpReadMu lock (see receiveSocket).
	udpReadWindow      = 1 * time.Second
	linkGrace          = 20 * time.Second
	// Bounded retries for the post-reconnect endpoint check: right after a
	// radio transition (LTE <-> Wi-Fi, doze resume) DNS and STUN often need a
	// few seconds to become usable, and a single failed check used to leave
	// the node advertising a stale endpoint until the next disconnect.
	endpointRefreshRetries    = 4
	endpointRefreshRetryDelay = 5 * time.Second
	// Mobile devices switch networks (Wi-Fi <-> LTE) without asking. Polling
	// the interface table is the only portable way to notice such a switch
	// within seconds; reacting to traffic failures alone takes 30-90 s because
	// half-open TCP and pinned UDP sockets keep pretending everything works.
	networkCheckInterval = 2 * time.Second
	roamRefreshMinGap    = 3 * time.Second
	// Interface flapping coalescing for the control channel watchdog.
	controlCheckInterval = 5 * time.Second
	// A healthy control WebSocket always sees traffic within this window: the
	// heartbeat request/reply cycle runs every heartbeat interval and the
	// coordinator pushes topology events. Anything quieter than that means the
	// TCP connection is half-open on a previous network.
	controlStaleTimeout = 45 * time.Second
	recoveryMinBackoff  = 10 * time.Second
	recoveryMaxBackoff  = 5 * time.Minute
	stunProbeTimeout    = 2 * time.Second
	maxRequest          = 32000
	maxResponse         = 48000
	maxUDPPort          = 65535

	symmetricBurstSize       = 500
	symmetricBurstTimeout    = 45 * time.Second
	symmetricScanDefaultStep = 200
	scanDelay                = 500 * time.Microsecond
	symmetricRetryDelay      = 2 * time.Second
	symmetricBurstRetries    = 4
	fastMagic                = "MIP1"
	fastHeader               = 49
	maxTUN                   = 1350
	fastBatchSize            = 32
	fastQueueSize            = 1024
	udpSendBatchSize         = 32
	udpSendQueueSize         = 256
	udpSocketBufferSize      = 4 << 20
	fastSeenCapacity         = 10000
	lanDiscoveryPort         = 37777
	lanDiscoveryInterval     = time.Minute
	lanDiscoveryBurstCount   = 5
	lanHoldTimeout           = 30 * time.Second
	lanProbeInterval         = 30 * time.Second // min spacing of unicast HELLO probes per peer
	lanProbeMaxAddrs         = 4                // candidates tried per peer per probe round
	lanAdvertiseMax          = 8                // LAN addresses reported to the coordinator
	localSubnetsRefresh      = 30 * time.Second
	initialTelemetryDelay    = 3 * time.Second
	aeadTag                  = 16
	maxFastFrame             = fastHeader + 12 + 12 + maxTUN + aeadTag
)

var fastMagicBytes = []byte(fastMagic)
var ipv4LimitedBroadcast = netip.MustParseAddr("255.255.255.255")

type config struct {
	server, token, inviteToken, role, nat, bind, endpoint, meshIP, tun, state, call, requestFile, pprofListen, controlCA string
	port, capacity, prefix, symmetricScanStep                                                                            int
	noRelay, autoTUN, debug, resetConfig, controlInsecure                                                                bool
	fastWorkers, deliverWorkers                                                                                          int
	statsInterval                                                                                                        time.Duration
	services, allows, bootstrapDNS                                                                                       multi
}
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type peer struct {
	ID           string               `json:"node_id"`
	Public       string               `json:"public_key"`
	NAT          string               `json:"nat_type"`
	Role         string               `json:"role"`
	Endpoint     string               `json:"endpoint"`
	Capacity     int                  `json:"capacity"`
	MeshIP       string               `json:"mesh_ip"`
	Name         string               `json:"name,omitempty"`
	Routes       []routeAdvertisement `json:"routes,omitempty"`
	DNSRecords   []dnsRecord          `json:"dns_records,omitempty"`
	last         net.Addr
	lastRX       time.Time
	lastLAN      *net.UDPAddr
	lastLANRX    time.Time
	lastPathLAN  bool      // the most recent datagram arrived from a local address
	lastLANProbe time.Time // last unicast HELLO probe round to the LAN candidates
	LANAddrs     []string  `json:"lan_addrs,omitempty"` // coordinator-advertised local addresses
	discovered   time.Time
	up           bool
	rttMS        float64
}
type routeAdvertisement struct {
	LAN     string `json:"lan_cidr"`
	Virtual string `json:"virtual_cidr"`
}
type dnsRecord struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	VirtualIP string `json:"virtual_ip"`
}
type edge struct {
	A    string  `json:"a"`
	B    string  `json:"b"`
	Cost float64 `json:"cost"`
}
type topology struct {
	Unchanged   bool            `json:"unchanged,omitempty"`
	Version     string          `json:"topology_version"`
	Self        peer            `json:"self"`
	Neighbors   []peer          `json:"neighbors"`
	Directory   []peer          `json:"directory"`
	Links       []edge          `json:"backbone_links"`
	Forwards    []portForward   `json:"forwards"`
	DNSUpstream string          `json:"dns_upstream,omitempty"`
	Firewall    *firewallConfig `json:"firewall,omitempty"`
}

// firewallConfig mirrors the coordinator-managed mesh firewall policy.
type firewallConfig struct {
	Mode  string   `json:"mode"`
	Ports []string `json:"ports"`
}

// fwRules is the immutable parsed form of the whitelist. A nil pointer in
// node.firewall means allow-all, so the default-mode per-packet cost on the
// TUN ingress path is a single atomic load and nil check.
type fwRules struct {
	tcp map[uint16]struct{}
	udp map[uint16]struct{}
}

func parseFirewallRules(c *firewallConfig) *fwRules {
	if c == nil || c.Mode != "whitelist" {
		return nil
	}
	r := &fwRules{tcp: map[uint16]struct{}{}, udp: map[uint16]struct{}{}}
	for _, raw := range c.Ports {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		port, proto := entry, ""
		if i := strings.IndexByte(entry, '/'); i >= 0 {
			port, proto = entry[:i], entry[i+1:]
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		switch proto {
		case "tcp":
			r.tcp[uint16(n)] = struct{}{}
		case "udp":
			r.udp[uint16(n)] = struct{}{}
		case "":
			r.tcp[uint16(n)] = struct{}{}
			r.udp[uint16(n)] = struct{}{}
		}
	}
	return r
}

// permits reports whether an inbound IPv4 packet from the mesh may enter the
// local stack. ICMP always passes (ping and path diagnostics stay usable);
// TCP/UDP must target a listed destination port; other protocols are dropped.
// Non-first fragments are dropped because the port lives in the first
// fragment — reassembly cannot complete without it anyway.
func (f *fwRules) permits(p []byte) bool {
	switch p[9] {
	case 1: // ICMP
		return true
	case 6, 17: // TCP, UDP
	default:
		return false
	}
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return false // non-first fragment: no port header to match
	}
	ihl := int(p[0]&15) * 4
	if ihl+4 > len(p) {
		return false
	}
	port := binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
	if p[9] == 6 {
		_, ok := f.tcp[port]
		return ok
	}
	_, ok := f.udp[port]
	return ok
}

type portForward struct {
	ID         int64  `json:"id"`
	Source     string `json:"source_node_id"`
	ListenHost string `json:"listen_host"`
	ListenPort int    `json:"listen_port"`
	Target     string `json:"target_node_id"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}
type subnetRoute struct {
	Virtual netip.Prefix
	LAN     netip.Prefix
	Owner   string
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
	peerID  [16]byte
	openAAD []byte
	sealAAD []byte
}
type reassembly struct {
	totalBytes int
	count      uint16
	chunks     map[uint16][]byte
	receivedAt time.Time
}
type symmetricReply struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}
type symmetricRelayTarget struct {
	id   string
	peer peer
}
type pingProbe struct {
	sent   time.Time
	peerID string
}
type fastFrame struct {
	data []byte
	addr *net.UDPAddr
}
type deliverFrame struct {
	source string
	data   []byte
}
type outboundDatagram struct {
	conn    *net.UDPConn
	data    []byte
	address *net.UDPAddr
}
type fastStats struct {
	receivedPackets, receivedBytes   atomic.Uint64
	queueDrops                       atomic.Uint64
	rxQueueDrops                     atomic.Uint64
	txQueueDrops                     atomic.Uint64
	sentPackets, sentBytes           atomic.Uint64
	deliveredPackets, deliveredBytes atomic.Uint64
	deliveryDrops                    atomic.Uint64
	controlRxPackets, controlRxBytes atomic.Uint64
	controlTxPackets, controlTxBytes atomic.Uint64
}
type node struct {
	c                  config
	requestedRole      string
	requestedNAT       string
	id                 *protocol.Identity
	idBinary           [16]byte
	packetPrefix       [4]byte
	packetCounter      atomic.Uint64
	key                []byte
	conn               *net.UDPConn
	connMu             sync.RWMutex
	symmetricConnMu    sync.RWMutex
	symmetricConns     map[string]*net.UDPConn
	receiveMu          sync.Mutex
	receiveCtx         context.Context
	receiveStarted     bool
	receiveSockets     map[*net.UDPConn]struct{}
	receiveWG          sync.WaitGroup
	lanConn            *net.UDPConn
	pendingLAN         map[string]*net.UDPAddr
	subnetsMu          sync.Mutex
	subnets            []netip.Prefix
	subnetsAt          time.Time
	udpReadMu          sync.RWMutex
	recoveryMu         sync.Mutex
	recoveryNext       time.Time
	recoveryFails      int
	control            *websocket.Conn
	controlConnected   bool
	controlMu          sync.Mutex
	controlRxAt        atomic.Int64
	roamRefreshAt      atomic.Int64
	closing            atomic.Bool
	controlCall        sync.Mutex
	controlReply       chan controlFrame
	pingMu             sync.Mutex
	pings              map[string]pingProbe
	linksRejected      atomic.Bool // coordinator cannot accept piggybacked link reports
	goarchRejected     atomic.Bool // coordinator cannot accept the goarch report
	lanAddrsRejected   atomic.Bool // coordinator cannot accept the lan_addrs report
	updating           atomic.Bool // a self-update download/swap is in progress
	telemetryMu        sync.Mutex
	lastTelemetrySent  time.Time
	lastTelemetryLinks []protocol.LinkMeasurement
	mu                 sync.RWMutex
	dnsUpstream        string
	routeMu            sync.Mutex
	dir                map[string]*peer
	neighbors          map[string]*peer
	links              []edge
	topologyVersion    string
	lastLoggedMeshIP   string
	lastLoggedRole     string
	routes             map[string]string
	meshNodes          map[netip.Addr]string
	subnetRoutes       []subnetRoute
	installedRoutes    map[string]bool
	seen               map[string]struct{}
	fastSeenMu         sync.Mutex
	fastSeen           map[[12]byte]struct{}
	fastSeenRing       [][12]byte
	fastSeenNext       int
	pending            map[string]chan serviceResult
	services           map[string]string
	allow              map[string]bool
	forwardMu          sync.Mutex
	forwardListeners   map[int64]net.Listener
	forwardRules       map[int64]portForward
	tunnels            map[string]net.Conn
	stop               context.CancelFunc
	tun                tunDevice
	tunLUID            uint64
	meshIPv4           atomic.Uint32
	firewall           atomic.Pointer[fwRules]
	startedAt          time.Time
	fastQueue          chan fastFrame
	udpSendQueue       chan outboundDatagram
	udpSendDone        <-chan struct{}
	udpSendPool        sync.Pool
	fastPool           sync.Pool
	sendPool           sync.Pool
	deliverQueues      []chan deliverFrame
	deliverPool        sync.Pool
	stats              fastStats

	topologyRefreshMu   sync.Mutex
	topologyRefreshNext time.Time

	sharedKeys     map[string]cachedKey
	reassembly     map[string]*reassembly
	routeRecompute atomic.Int64

	symmetricMu         sync.Mutex
	symmetricReady      bool
	symmetricScans      map[string]chan struct{}
	symmetricSessions   map[string]string
	symmetricAckWaiters map[string]chan struct{}
	symmetricConnected  map[string]bool
	symmetricBurstAt    map[string]time.Time
	symmetricBurstSess  map[string]string
	symmetricScanSlots  chan struct{}
	edgeRetryMu         sync.Mutex
	edgeRetries         map[string]bool
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--add-autostart" || arg == "--del-autostart" {
			var err error
			if arg == "--add-autostart" {
				startupArgs := make([]string, 0, len(os.Args)-2)
				for _, a := range os.Args[1:] {
					if a != "--add-autostart" {
						startupArgs = append(startupArgs, a)
					}
				}
				err = autostart.Install("mesh-node", startupArgs, os.Environ())
			} else {
				err = autostart.Remove("mesh-node")
			}
			if err != nil {
				log.Fatal(err)
			}
			log.Println("autostart updated")
			return
		}
	}
	log.Printf("[mesh-node] loading configuration; use --server and --network-token/--invite-token to skip interactive prompts")
	// Remove the previous version left behind by a self-update (Windows only;
	// no-op on other platforms). Runs before anything else so restarts are
	// always clean.
	cleanupUpdateBackup()
	c := parse()
	if c.token != "" && len(c.token) < 24 {
		log.Fatal("--network-token must be at least 24 characters")
	}
	n, e := newNode(c)
	if e != nil {
		log.Fatal(e)
	}
	defer n.close()
	log.Printf("[%s] Mesh node %s", n.id.ID[:8], n.id.ID)
	if c.debug {
		n.debugStartupNetwork()
	}
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

// debugStartupNetwork prints diagnostics before STUN/WebSocket traffic starts.
// It is intentionally best-effort: diagnostics must never prevent startup.
func (n *node) debugStartupNetwork() {
	n.logf("debug startup: server=%s bind=%s udp=%s role=%s nat=%s tun=%s auto_tun=%t", n.c.server, n.c.bind, n.conn.LocalAddr(), n.c.role, n.c.nat, n.c.tun, n.c.autoTUN)
	interfaces, err := net.Interfaces()
	if err != nil {
		n.logf("debug network interfaces: %v", err)
	} else {
		for _, iface := range interfaces {
			addrs, addrErr := iface.Addrs()
			if addrErr != nil {
				n.logf("debug interface %s flags=%s addresses unavailable: %v", iface.Name, iface.Flags, addrErr)
				continue
			}
			n.logf("debug interface %s index=%d flags=%s mtu=%d addresses=%v", iface.Name, iface.Index, iface.Flags, iface.MTU, addrs)
		}
	}
	if u, err := url.Parse(strings.TrimRight(n.c.server, "/")); err != nil {
		n.logf("debug coordinator URL parse failed: %v", err)
	} else {
		host := u.Hostname()
		n.logf("debug coordinator scheme=%s host=%s port=%s", u.Scheme, host, u.Port())
		if host != "" {
			addresses, resolveErr := meshResolver().LookupHost(context.Background(), host)
			if resolveErr != nil {
				n.logf("debug DNS coordinator %s failed: %v", host, resolveErr)
			} else {
				n.logf("debug DNS coordinator %s -> %v", host, addresses)
			}
		}
	}
	for _, stun := range []string{"stun.nextcloud.com:3478", "stun.miwifi.com:3478", "stun.sipgate.net:3478"} {
		addresses, resolveErr := meshResolver().LookupHost(context.Background(), strings.TrimSuffix(strings.Split(stun, ":")[0], "]"))
		if resolveErr != nil {
			n.logf("debug DNS STUN %s failed: %v", stun, resolveErr)
		} else {
			n.logf("debug DNS STUN %s -> %v", stun, addresses)
		}
	}
}
func parse() config {
	var c config
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	f.StringVar(&c.server, "server", "", "Control-plane base URL")
	f.Var(&c.bootstrapDNS, "bootstrap-dns", "IPv4 DNS server for startup hostnames (repeatable, e.g. 1.1.1.1:53)")
	f.StringVar(&c.token, "network-token", "", "shared network token")
	f.StringVar(&c.inviteToken, "invite-token", "", "one-time coordinator invitation token")
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
	f.StringVar(&c.state, "state-dir", unifiedStateFile, "state JSON file (legacy directory paths are migrated automatically)")
	f.Var(&c.services, "service", "publish NAME=HOST:PORT")
	f.Var(&c.allows, "allow-node", "allow node ID for services")
	f.BoolVar(&c.noRelay, "no-relay", false, "disable relay")
	f.BoolVar(&c.debug, "debug", false, "log data-plane packet decisions")
	f.IntVar(&c.symmetricScanStep, "symmetric-scan-step", symmetricScanDefaultStep, "port interval for symmetric NAT scan")
	f.IntVar(&c.fastWorkers, "fast-workers", 0, "fast packet workers (0 = up to 2, max 16)")
	f.IntVar(&c.deliverWorkers, "deliver-workers", 0, "TUN delivery workers (0 = up to 4, max 16)")
	f.DurationVar(&c.statsInterval, "stats-interval", 0, "log fast-path throughput and queue statistics (0 = off)")
	f.StringVar(&c.pprofListen, "pprof-listen", "", "local pprof listener, e.g. 127.0.0.1:6060")
	f.StringVar(&c.call, "call", "", "NODE_ID:SERVICE to call")
	f.StringVar(&c.requestFile, "request-file", "", "request file")
	f.StringVar(&c.controlCA, "control-ca-file", "", "PEM CA bundle for an HTTPS/WSS coordinator")
	f.BoolVar(&c.controlInsecure, "control-insecure-skip-verify", false, "skip HTTPS certificate verification (testing only)")
	f.BoolVar(&c.resetConfig, "reset-config", false, "delete saved interactive configuration and ask again")
	f.Parse(os.Args[1:])
	if c.resetConfig {
		for _, path := range []string{unifiedStateFile, interactiveConfigFile} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Fatal("reset configuration: ", err)
			}
		}
		fmt.Println("Saved configuration reset. Run without parameters to configure it again.")
		os.Exit(0)
	}
	if saved, err := loadInteractiveConfig(); err == nil {
		if len(os.Args) == 1 {
			c = saved
			// Scan tuning is deliberately a command-line setting and is not
			// stored with interactive connection settings.
			c.symmetricScanStep = symmetricScanDefaultStep
			// Interactive nodes are TUN endpoints by default. Migrate earlier
			// saved configurations that predate this default.
			if c.tun == "" {
				c.tun = "mesh0"
				c.autoTUN = true
				_ = saveInteractiveConfig(c)
			}
		} else { // Keep CLI tuning flags, but reuse saved connection and identity settings.
			if c.server == "" {
				c.server = saved.server
			}
			if c.token == "" {
				c.token = saved.token
			}
			if c.inviteToken == "" {
				c.inviteToken = saved.inviteToken
			}
			if c.state == unifiedStateFile {
				c.state = saved.state
			}
			if c.tun == "" {
				c.tun = saved.tun
			}
			if c.nat == "auto" {
				c.nat = saved.nat
			}
			if c.bind == "0.0.0.0" {
				c.bind = saved.bind
			}
			// Never restore a previously observed public endpoint; rediscover it.
			if c.meshIP == "" {
				c.meshIP = saved.meshIP
			}
			if c.port == 0 {
				c.port = saved.port
			}
			if c.capacity == 1 {
				c.capacity = saved.capacity
			}
			if c.prefix == 24 {
				c.prefix = saved.prefix
			}
			if !c.autoTUN {
				c.autoTUN = saved.autoTUN
			}
			if !c.noRelay {
				c.noRelay = saved.noRelay
			}
		}
	} else if c.server == "" || (c.token == "" && c.inviteToken == "") {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("saved configuration needs replacement: %v", err)
		}
		debug, stats := c.debug, c.statsInterval
		c = askInteractiveConfig()
		c.debug, c.statsInterval = debug, stats
		if err := saveInteractiveConfig(c); err != nil {
			log.Fatal("save configuration: ", err)
		}
	}
	if c.server == "" || (c.token == "" && c.inviteToken == "") {
		f.Usage()
		os.Exit(2)
	}
	if c.role != "auto" && c.role != "client" && c.role != "superpeer" {
		log.Fatal("invalid --role")
	}
	if c.statsInterval < 0 {
		log.Fatal("--stats-interval must not be negative")
	}
	if c.symmetricScanStep < 1 || c.symmetricScanStep > maxUDPPort {
		log.Fatalf("--symmetric-scan-step must be between 1 and %d", maxUDPPort)
	}
	return c
}

const (
	unifiedStateFile      = "mesh-node.json"
	interactiveConfigFile = "mesh-node-config.json"
)

type savedConfig struct {
	Server, Token, InviteToken, Role, NAT, Bind, Endpoint, MeshIP, TUN, State, ControlCA string
	Port, Capacity, Prefix, SymmetricScanStep                                            int
	NoRelay, AutoTUN, Debug, ControlInsecure                                             bool
	PrivateKey                                                                           string `json:"private_key,omitempty"`
}

func loadInteractiveConfig() (config, error) {
	var c config
	path := unifiedStateFile
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		path = interactiveConfigFile
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return c, err
	}
	var saved savedConfig
	err = json.Unmarshal(b, &saved)
	if err == nil {
		// Debug is intentionally not restored from disk: it is a temporary
		// diagnostic mode enabled only by an explicit --debug flag.
		// Public NAT mappings are not persistent credentials. Always rediscover
		// the endpoint after a process/NAT restart instead of reusing stale JSON.
		step := saved.SymmetricScanStep
		if step == 0 {
			step = symmetricScanDefaultStep
		}
		c = config{server: saved.Server, token: saved.Token, inviteToken: saved.InviteToken, role: saved.Role, nat: saved.NAT, bind: saved.Bind, endpoint: "", meshIP: saved.MeshIP, tun: saved.TUN, state: unifiedStateFile, controlCA: saved.ControlCA, port: saved.Port, capacity: saved.Capacity, prefix: saved.Prefix, symmetricScanStep: step, noRelay: saved.NoRelay, autoTUN: saved.AutoTUN, debug: false, controlInsecure: saved.ControlInsecure}
		if saved.PrivateKey == "" && saved.State != "" {
			if legacy, readErr := os.ReadFile(filepath.Join(saved.State, "identity.json")); readErr == nil {
				var identity struct {
					PrivateKey string `json:"private_key"`
				}
				if json.Unmarshal(legacy, &identity) == nil {
					saved.PrivateKey = identity.PrivateKey
				}
			}
		}
		if saved.PrivateKey != "" || path == interactiveConfigFile {
			if saveErr := saveInteractiveConfigWithKey(c, saved.PrivateKey); saveErr != nil {
				return config{}, saveErr
			}
		}
		if c.server == "" || (c.token == "" && c.inviteToken == "") {
			return config{}, fmt.Errorf("saved configuration is empty; run --reset-config once")
		}
	}
	return c, err
}
func saveInteractiveConfig(c config) error {
	return saveInteractiveConfigWithKey(c, "")
}
func saveInteractiveConfigWithKey(c config, privateKey string) error {
	if privateKey == "" {
		if b, err := os.ReadFile(unifiedStateFile); err == nil {
			var existing savedConfig
			if json.Unmarshal(b, &existing) == nil {
				privateKey = existing.PrivateKey
			}
		}
	}
	saved := savedConfig{Server: c.server, Token: c.token, InviteToken: c.inviteToken, Role: c.role, NAT: c.nat, Bind: c.bind, Endpoint: c.endpoint, MeshIP: c.meshIP, TUN: c.tun, State: unifiedStateFile, ControlCA: c.controlCA, Port: c.port, Capacity: c.capacity, Prefix: c.prefix, SymmetricScanStep: c.symmetricScanStep, NoRelay: c.noRelay, AutoTUN: c.autoTUN, Debug: false, ControlInsecure: c.controlInsecure, PrivateKey: privateKey}
	b, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(unifiedStateFile, b, 0600)
}
func askInteractiveConfig() config {
	fmt.Fprintln(os.Stderr, "[mesh-node] first start: waiting for configuration input; network connection has not started yet")
	in := bufio.NewReader(os.Stdin)
	ask := func(label, fallback string) string {
		fmt.Printf("%s [%s]: ", label, fallback)
		v, _ := in.ReadString('\n')
		v = strings.TrimSpace(v)
		if v == "" {
			return fallback
		}
		return v
	}
	c := config{server: ask("Coordinator URL", "http://127.0.0.1:8001"), role: "auto", nat: "auto", bind: "0.0.0.0", state: unifiedStateFile, tun: "mesh0", autoTUN: true, prefix: 24, capacity: 1, symmetricScanStep: symmetricScanDefaultStep}
	credential := ask("Network token or 6-character invite", "")
	if len(credential) == 6 {
		c.inviteToken = credential
	} else {
		c.token = credential
	}
	c.role = ask("Role (auto/client/superpeer)", "auto")
	return c
}
// loadIdentity loads the persistent node key, creating one on first use.
func loadIdentity(dir string) (*protocol.Identity, error) {
	if b, e := os.ReadFile(dir); e == nil {
		var x struct {
			Private string `json:"private_key"`
		}
		if json.Unmarshal(b, &x) == nil && x.Private != "" {
			raw, e := protocol.B64Decode(x.Private)
			if e != nil {
				return nil, e
			}
			return protocol.ParsePrivateDER(raw)
		}
		// The unified file exists but has no identity yet; generate one below.
		if filepath.Base(dir) == unifiedStateFile {
			return createUnifiedIdentity(dir)
		}
	}
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

func createUnifiedIdentity(path string) (*protocol.Identity, error) {
	i, err := protocol.NewIdentity()
	if err != nil {
		return nil, err
	}
	raw, err := protocol.MarshalPrivateDER(i)
	if err != nil {
		return nil, err
	}
	var saved savedConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &saved); err != nil {
		return nil, err
	}
	saved.PrivateKey = protocol.B64Encode(raw)
	encoded, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return nil, err
	}
	return i, os.WriteFile(path, encoded, 0600)
}
// newNode initializes runtime state and network resources from configuration.
func newNode(c config) (*node, error) {
	id, e := loadIdentity(c.state)
	if e != nil {
		return nil, e
	}
	decodedID, e := hex.DecodeString(id.ID)
	if e != nil || len(decodedID) != 16 {
		return nil, errors.New("identity has an invalid node ID")
	}
	var idBinary [16]byte
	copy(idBinary[:], decodedID)
	a, e := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", c.bind, c.port))
	if e != nil {
		return nil, e
	}
	conn, e := net.ListenUDP("udp4", a)
	if e != nil {
		return nil, e
	}
	configureUDPSocket(conn)
	k := sha256.Sum256([]byte(c.token))
	n := &node{
		c:                   c,
		requestedRole:       c.role,
		requestedNAT:        c.nat,
		id:                  id,
		idBinary:            idBinary,
		key:                 k[:],
		conn:                conn,
		symmetricConns:      map[string]*net.UDPConn{},
		receiveSockets:      map[*net.UDPConn]struct{}{},
		dir:                 map[string]*peer{},
		pendingLAN:          map[string]*net.UDPAddr{},
		neighbors:           map[string]*peer{},
		routes:              map[string]string{},
		meshNodes:           map[netip.Addr]string{},
		installedRoutes:     map[string]bool{},
		seen:                map[string]struct{}{},
		fastSeen:            make(map[[12]byte]struct{}, fastSeenCapacity),
		fastSeenRing:        make([][12]byte, 0, fastSeenCapacity),
		pending:             map[string]chan serviceResult{},
		services:            map[string]string{},
		allow:               map[string]bool{"*": true},
		forwardListeners:    map[int64]net.Listener{},
		forwardRules:        map[int64]portForward{},
		tunnels:             map[string]net.Conn{},
		startedAt:           time.Now(),
		sharedKeys:          map[string]cachedKey{},
		reassembly:          map[string]*reassembly{},
		symmetricScans:      map[string]chan struct{}{},
		symmetricSessions:   map[string]string{},
		symmetricAckWaiters: map[string]chan struct{}{},
		symmetricConnected:  map[string]bool{},
		symmetricBurstAt:    map[string]time.Time{},
		symmetricBurstSess:  map[string]string{},
		symmetricScanSlots:  make(chan struct{}, 2),
		edgeRetries:         map[string]bool{},
		pings:               map[string]pingProbe{},
	}
	if _, e = rand.Read(n.packetPrefix[:]); e != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("initialize packet ID sequence: %w", e)
	}
	n.sendPool.New = func() any { return make([]byte, maxFastFrame) }
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

// UDP has no backpressure. Larger kernel queues absorb short bursts while the
// workers are decrypting or routing an earlier batch. These calls are
// best-effort because operating systems may clamp the requested size.
func configureUDPSocket(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	_ = conn.SetReadBuffer(udpSocketBufferSize)
	_ = conn.SetWriteBuffer(udpSocketBufferSize)
}

type controlFrame struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Status int             `json:"status,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
}

// connectControl opens the persistent WebSocket used for coordinator events.
func (n *node) connectControl() (bool, error) {
	if n.control != nil {
		return false, nil
	}
	u, err := url.Parse(strings.TrimRight(n.c.server, "/") + "/v1/ws")
	if err != nil {
		return false, err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return false, fmt.Errorf("unsupported control-plane URL scheme %q", u.Scheme)
	}
	n.logf("connecting control WebSocket via %s", u.String())
	origin := "http://" + u.Host
	wsConfig, err := websocket.NewConfig(u.String(), origin)
	if err != nil {
		return false, err
	}
	wsConfig.Dialer = &net.Dialer{Timeout: 10 * time.Second, Resolver: meshResolver(n.c.bootstrapDNS...)}
	wsConfig.Header.Set("X-Mesh-Token", n.c.token)
	if n.c.inviteToken != "" {
		wsConfig.Header.Set("X-Mesh-Invite", n.c.inviteToken)
	}
	if u.Scheme == "wss" {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		pool, err := controlCertPool(n.c.controlCA)
		if err != nil {
			return false, err
		}
		tlsConfig.RootCAs = pool
		if n.c.controlInsecure {
			tlsConfig.InsecureSkipVerify = true
			n.logf("WARNING: TLS certificate verification is disabled")
		}
		wsConfig.TlsConfig = tlsConfig
	}
	ws, err := websocket.DialConfig(wsConfig)
	if err != nil {
		return false, fmt.Errorf("connect control websocket: %w", err)
	}
	reconnected := n.controlConnected
	n.control = ws
	n.controlConnected = true
	n.controlReply = make(chan controlFrame, 1)
	go n.readControl(ws, n.controlReply)
	n.logf("control WebSocket connected")
	return reconnected, nil
}

// meshResolver avoids Android configurations that point libc DNS at an
// unavailable IPv6 loopback resolver (::1). It deliberately resolves only
// IPv4 addresses because the mesh transport is IPv4/UDP based.
func meshResolver(bootstrap ...string) *net.Resolver {
	servers := []string{}
	if system := systemResolver(); system != "" {
		servers = append(servers, system)
	}
	for _, value := range bootstrap {
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			host, port = value, "53"
		}
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil && ip.To4() != nil {
			servers = append(servers, net.JoinHostPort(ip.String(), port))
		}
	}
	// Last-resort public resolver for bootstrap connectivity.
	servers = append(servers, "8.8.8.8:53")
	var index atomic.Uint32
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		for i := 0; i < len(servers); i++ {
			server := servers[int(index.Add(1)-1)%len(servers)]
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp4", server)
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("no IPv4 DNS server available")
	}}
}

func controlCertPool(explicit string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if explicit != "" {
		pem, err := os.ReadFile(explicit)
		if err != nil {
			return nil, fmt.Errorf("read --control-ca-file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate found in --control-ca-file")
		}
		return pool, nil
	}
	// Termux keeps its CA bundle outside the Android system paths. Add known
	// OS/package-manager bundles without weakening verification or accepting
	// an insecure TLS connection.
	paths := []string{
		os.Getenv("SSL_CERT_FILE"),
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/cert.pem",
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		pem, readErr := os.ReadFile(path)
		if readErr == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	return pool, nil
}

func (n *node) readControl(ws *websocket.Conn, replies chan<- controlFrame) {
	for {
		var frame controlFrame
		if err := websocket.JSON.Receive(ws, &frame); err != nil {
			n.controlMu.Lock()
			if n.control == ws {
				n.control = nil
			}
			n.controlMu.Unlock()
			// Clearing the pointer alone leaked one file descriptor per
			// reconnect and left the dead socket in place. Close it and start
			// reconnecting immediately instead of waiting up to a full
			// heartbeat (plus two send/reply timeouts) for the next register.
			_ = ws.Close()
			if !n.closing.Load() {
				go n.pokeControlReconnect()
			}
			return
		}
		n.controlRxAt.Store(time.Now().UnixNano())
		if frame.Event == "topology" {
			var t topology
			if err := json.Unmarshal(frame.Body, &t); err != nil {
				n.logf("invalid pushed topology: %v", err)
			} else {
				n.applyTopology(t)
			}
			continue
		}
		if frame.Event == "symmetric_scan" {
			var event struct {
				PeerID    string `json:"peer_node_id"`
				SessionID string `json:"session_id"`
				Endpoint  string `json:"endpoint"`
			}
			if err := json.Unmarshal(frame.Body, &event); err != nil {
				n.logf("invalid symmetric scan event: %v", err)
			} else {
				go n.handleSymmetricScanEvent(event.PeerID, event.SessionID, event.Endpoint)
			}
			continue
		}
		if frame.Event == "symmetric_scan_ack" {
			var event struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(frame.Body, &event) == nil {
				n.symmetricMu.Lock()
				waiter := n.symmetricAckWaiters[event.SessionID]
				n.symmetricMu.Unlock()
				if waiter != nil {
					select {
					case waiter <- struct{}{}:
					default:
					}
				}
			}
			continue
		}
		if frame.Event == "update" {
			// The coordinator wants this node to download a new binary and
			// restart into it. Handled in a goroutine so the control loop
			// keeps servicing hole-punching traffic during the download.
			go n.handleUpdateEvent(frame.Body)
			continue
		}
		select {
		case replies <- frame:
		default:
			n.logf("unexpected control-plane reply discarded")
		}
	}
}

// pokeControlReconnect rebuilds the control channel as soon as the reader
// observes a dead connection. Without it a node stayed offline for up to a
// heartbeat interval even though it had already lost the coordinator. The
// jitter prevents every node from dialing in the same millisecond after a
// coordinator restart.
func (n *node) pokeControlReconnect() {
	var jitter [2]byte
	if _, err := rand.Read(jitter[:]); err == nil {
		time.Sleep(time.Duration(binary.BigEndian.Uint16(jitter[:])%2000) * time.Millisecond)
	}
	if n.closing.Load() {
		return
	}
	n.controlMu.Lock()
	alive := n.control != nil
	n.controlMu.Unlock()
	if alive {
		return // a concurrent request already reconnected
	}
	if err := n.register(); err != nil {
		n.logf("control reconnect after disconnect failed: %v", err)
	}
}

func androidRuntime() bool {
	if runtime.GOOS == "android" {
		return true
	}
	// Android binaries are often built as linux/arm64 for Termux/Magisk.
	// Detect the platform by the Android property service in that case.
	if _, err := os.Stat("/system/bin/getprop"); err == nil {
		return true
	}
	if _, err := exec.LookPath("getprop"); err == nil {
		return true
	}
	return false
}

// request sends compact JSON frames over one long-lived WebSocket. A failed
// connection is recreated once, which also handles NAT or server restarts.
func (n *node) request(method, path string, in, out any) error {
	var body json.RawMessage
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
	}
	n.controlCall.Lock()
	defer n.controlCall.Unlock()
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		n.controlMu.Lock()
		reconnected, err := n.connectControl()
		if err != nil {
			n.controlMu.Unlock()
			last = err
			continue
		}
		ws, replies := n.control, n.controlReply
		// A request that timed out may still deliver its reply later. Without
		// draining, the next request would consume that stale response and
		// act on a body/status that belongs to an earlier operation.
	drain:
		for {
			select {
			case <-replies:
			default:
				break drain
			}
		}
		frame := controlFrame{Method: method, Path: path, Body: body}
		_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Send(ws, frame); err != nil {
			n.controlMu.Unlock()
			last = err
		} else {
			_ = ws.SetWriteDeadline(time.Time{})
			n.controlMu.Unlock()
			responseTimer := time.NewTimer(10 * time.Second)
			select {
			case reply := <-replies:
				if !responseTimer.Stop() {
					<-responseTimer.C
				}
				if reconnected {
					go n.refreshEndpointAfterControlReconnect()
				}
				if reply.Status < 200 || reply.Status > 299 {
					return fmt.Errorf("control plane: status %d: %s", reply.Status, reply.Error)
				}
				if out == nil {
					return nil
				}
				return json.Unmarshal(reply.Body, out)
			case <-responseTimer.C:
				last = errors.New("control websocket response timed out")
				// Frames are still arriving, so the coordinator is slow (for
				// example waiting on the single SQLite writer) rather than
				// unreachable. Keep the socket so the retry reuses it;
				// reconnecting here dropped healthy connections and turned one
				// slow reply into a reconnect and endpoint-refresh storm.
				if time.Since(time.Unix(0, n.controlRxAt.Load())) < 5*time.Second {
					continue
				}
			}
		}
		n.controlMu.Lock()
		if n.control == ws {
			_ = n.control.Close()
			n.control = nil
		}
		n.controlMu.Unlock()
	}
	return fmt.Errorf("control websocket request: %w", last)
}

// refreshEndpointAfterControlReconnect is intentionally asynchronous. A
// restored WebSocket must not wait for STUN or topology rebuilding. A fresh
// UDP socket is used because Android may keep the old socket on Wi-Fi after a
// switch to LTE.
func (n *node) refreshEndpointAfterControlReconnect() {
	n.refreshEndpointAttempt(1)
}

// refreshEndpointAttempt re-checks the public UDP endpoint after a control
// reconnect. Failures are retried with a fixed delay up to
// endpointRefreshRetries times; recoveryMu.TryLock keeps overlapping
// attempts (late retries vs. a newer reconnect) mutually exclusive.
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
	previousEndpoint := n.c.endpoint
	if endpoint == previousEndpoint {
		return
	}
	ipChanged := endpointIPChanged(previousEndpoint, endpoint)
	n.logf("control reconnect: UDP endpoint changed %s -> %s", previousEndpoint, endpoint)
	// A port-only change is a normal NAT rebinding. Do not tear down the
	// transport here: for symmetric NAT that would start a new scan and
	// unnecessarily reconnect all existing links. The coordinator receives
	// the fresh endpoint through the heartbeat, while the current transport
	// remains intact. Network/IP changes still use the full recovery path
	// below.
	if !ipChanged {
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
		n.logf("control reconnect: TUN network restore failed: %v", err)
	}
	n.c.endpoint = endpoint
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	if err := n.register(); err != nil {
		n.logf("control reconnect: re-register failed: %v", err)
		return
	}
	if err := n.bootstrap(); err != nil {
		n.logf("control reconnect: topology refresh failed: %v", err)
		return
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.logf("control reconnect: symmetric handshake did not complete")
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

// register announces this node and refreshes its coordinator lease.
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
// bootstrap fetches the current peer list and forwarding topology.
func (n *node) bootstrap() error {
	n.mu.RLock()
	version := n.topologyVersion
	n.mu.RUnlock()
	path := "/v1/bootstrap/" + n.id.ID
	// Older coordinators ignore this optional body and return a full snapshot.
	var condition any
	if version != "" {
		condition = map[string]string{"version": version}
	}
	var t topology
	if e := n.request("GET", path, condition, &t); e != nil {
		// The coordinator intentionally hides stale nodes from topology. A
		// short control-plane/NAT interruption can therefore make bootstrap
		// return 404 even though the node still exists. Refresh the lease and
		// retry once instead of terminating the client.
		if strings.Contains(e.Error(), "404: unknown node") {
			n.logf("bootstrap returned unknown node; refreshing registration lease")
			if registerErr := n.register(); registerErr != nil {
				return fmt.Errorf("bootstrap unknown node; re-register failed: %w", registerErr)
			}
			if retryErr := n.request("GET", path, condition, &t); retryErr != nil {
				return retryErr
			}
		} else {
			return e
		}
	}
	n.applyTopology(t)
	return nil
}
// applyTopology updates peer state and routes from a coordinator snapshot.
func (n *node) applyTopology(t topology) {
	n.mu.RLock()
	// A push may have installed a newer view while a conditional request
	// was in flight. A version-only response must never replace that view.
	unchanged := t.Unchanged || (t.Version != "" && n.topologyVersion == t.Version)
	n.mu.RUnlock()
	if unchanged {
		// A network switch can remove OS routes without changing the
		// coordinator topology version.
		if n.tun != nil && n.c.autoTUN {
			if err := n.forceTUNRouteSync(); err != nil {
				n.logf("TUN route resync failed: %v", err)
			}
		}
		return
	}
	n.mu.Lock()
	n.dnsUpstream = t.DNSUpstream
	old := n.neighbors
	n.dir = map[string]*peer{}
	n.meshNodes = map[netip.Addr]string{}
	n.subnetRoutes = nil
	for _, v := range t.Directory {
		p := v
		n.dir[p.ID] = &p
		if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
			n.meshNodes[ip] = p.ID
		}
		for _, route := range p.Routes {
			virtual, e1 := netip.ParsePrefix(route.Virtual)
			lan, e2 := netip.ParsePrefix(route.LAN)
			if e1 == nil && e2 == nil && virtual.Addr().Is4() && virtual.Bits() == lan.Bits() {
				n.subnetRoutes = append(n.subnetRoutes, subnetRoute{virtual.Masked(), lan.Masked(), p.ID})
			}
		}
	}
	p := t.Self
	n.dir[p.ID] = &p
	if ip, err := netip.ParseAddr(p.MeshIP); err == nil {
		n.meshNodes[ip] = p.ID
	}
	for _, route := range p.Routes {
		virtual, e1 := netip.ParsePrefix(route.Virtual)
		lan, e2 := netip.ParsePrefix(route.LAN)
		if e1 == nil && e2 == nil && virtual.Addr().Is4() && virtual.Bits() == lan.Bits() {
			n.subnetRoutes = append(n.subnetRoutes, subnetRoute{virtual.Masked(), lan.Masked(), p.ID})
		}
	}
	n.neighbors = map[string]*peer{}
	type lanHello struct {
		id   string
		addr *net.UDPAddr
	}
	lanHellos := make([]lanHello, 0, 2)
	lanHellosBase := len(lanHellos) // probe budget below counts only new candidates
	for _, v := range t.Neighbors {
		p := v
		p.discovered = time.Now()
		if q := old[p.ID]; q != nil {
			p.last = q.last
			p.lastRX = q.lastRX
			p.up = q.up
			p.discovered = q.discovered
			p.lastLAN = q.lastLAN
			p.lastLANRX = q.lastLANRX
			p.lastPathLAN = q.lastPathLAN
			p.lastLANProbe = q.lastLANProbe
		}
		// Coordinator-assisted LAN discovery: broadcasts cannot cross a
		// router, so a peer in an adjacent subnet of the same physical
		// network (cascaded routers) is probed by unicasting HELLO to the
		// LAN addresses it advertised. touch() flips the path to LAN only
		// when a reply actually arrives from a local address; a silent
		// candidate (segmentation, AP isolation, non-routable subnet) never
		// disturbs the working WAN path.
		if len(v.LANAddrs) > 0 {
			probedAt := time.Now()
			if probedAt.Sub(p.lastLANProbe) >= lanProbeInterval && !freshLAN(&p, probedAt) {
				p.lastLANProbe = probedAt
				for _, raw := range v.LANAddrs {
					if len(lanHellos)-lanHellosBase >= lanProbeMaxAddrs {
						break
					}
					addr, err := net.ResolveUDPAddr("udp4", raw)
					if err != nil || addr.IP == nil {
						continue
					}
					// Candidates equal to lastLAN are re-probed deliberately:
					// a peer that moved away and came back on the same address
					// must be re-found, and the interval above keeps the
					// retry cost at one small datagram per candidate.
					p.lastLAN = copyUDPAddr(addr)
					lanHellos = append(lanHellos, lanHello{id: p.ID, addr: copyUDPAddr(addr)})
				}
			}
		}
		if candidate := n.pendingLAN[p.ID]; candidate != nil {
			delete(n.pendingLAN, p.ID)
			// Candidate only: lastLANRX is confirmed by touch() once traffic
			// really arrives from the LAN address.
			p.lastLAN = candidate
			p.last = candidate
			lanHellos = append(lanHellos, lanHello{id: p.ID, addr: candidate})
		}
		n.neighbors[p.ID] = &p
	}
	n.links = t.Links
	n.firewall.Store(parseFirewallRules(t.Firewall))
	n.topologyVersion = t.Version
	n.routes = n.buildRoutes()
	n.mu.Unlock()
	for _, hello := range lanHellos {
		n.logf("LAN endpoint candidate for %s: %s", hello.id[:8], hello.addr)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, hello.id, map[string]any{"public_key": n.id.Public}), hello.addr)
	}
	// The topology just changed: a new peer may sit on this very LAN (its
	// broadcasts may already have been missed while it was bootstrapping),
	// so announce immediately instead of waiting for the next tick.
	n.broadcastLANDiscovery()
	n.syncPortForwards(t.Forwards)
	n.cancelObsoleteSymmetricScans()
	if n.c.debug {
		n.mu.RLock()
		for _, r := range n.subnetRoutes {
			n.logf("virtual route %s -> %s (LAN %s)", r.Virtual, r.Owner, r.LAN)
		}
		n.mu.RUnlock()
	}
	if n.tun != nil && n.c.autoTUN {
		if err := n.syncTUNRoutes(); err != nil {
			n.logf("subnet route sync failed: %v", err)
		}
	}
	n.logf("topology=%s neighbors=%d", t.Version, len(t.Neighbors))
}

func tunnelKey(peer, id string) string { return peer + ":" + id }

func (n *node) syncPortForwards(rules []portForward) {
	n.forwardMu.Lock()
	n.forwardRules = map[int64]portForward{}
	for _, rule := range rules {
		n.forwardRules[rule.ID] = rule
	}
	n.forwardMu.Unlock()
	want := map[int64]portForward{}
	for _, rule := range rules {
		if rule.Source == n.id.ID {
			want[rule.ID] = rule
		}
	}
	n.forwardMu.Lock()
	for id, listener := range n.forwardListeners {
		if _, ok := want[id]; !ok {
			_ = listener.Close()
			delete(n.forwardListeners, id)
			n.logf("reverse forward %d stopped", id)
		}
	}
	for id, rule := range want {
		if _, ok := n.forwardListeners[id]; ok {
			continue
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(rule.ListenHost, strconv.Itoa(rule.ListenPort)))
		if err != nil {
			n.logf("reverse forward %d cannot listen: %v", id, err)
			continue
		}
		n.forwardListeners[id] = listener
		go n.acceptPortForward(listener, rule)
		n.logf("reverse forward %s -> %s:%d via %s", listener.Addr(), rule.TargetHost, rule.TargetPort, rule.Target[:8])
	}
	n.forwardMu.Unlock()
}
func (n *node) acceptPortForward(listener net.Listener, rule portForward) {
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		go n.openTunnel(c, rule)
	}
}
func (n *node) openTunnel(c net.Conn, rule portForward) {
	id := protocol.NewPacket("", "", "", nil).ID
	n.forwardMu.Lock()
	n.tunnels[tunnelKey(rule.Target, id)] = c
	n.forwardMu.Unlock()
	defer n.closeTunnel(rule.Target, id)
	if !n.encrypted(rule.Target, "TUNNEL_OPEN", map[string]any{"id": id, "host": rule.TargetHost, "port": rule.TargetPort}, "") {
		return
	}
	n.copyTunnel(c, rule.Target, id)
}
func (n *node) copyTunnel(c net.Conn, peer, id string) {
	b := make([]byte, 900)
	for {
		count, err := c.Read(b)
		if count > 0 && !n.encrypted(peer, "TUNNEL_DATA", map[string]any{"id": id, "data": protocol.B64Encode(b[:count])}, "") {
			return
		}
		if err != nil {
			return
		}
	}
}
func (n *node) closeTunnel(peer, id string) {
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(peer, id)]
	delete(n.tunnels, tunnelKey(peer, id))
	n.forwardMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	_ = n.encrypted(peer, "TUNNEL_CLOSE", map[string]any{"id": id}, "")
}
func (n *node) tunnelOpen(src string, body map[string]any) {
	id, _ := body["id"].(string)
	host, _ := body["host"].(string)
	port, ok := body["port"].(float64)
	if id == "" || host == "" || !ok || port < 1 || port > 65535 {
		return
	}
	n.forwardMu.Lock()
	allowed := false
	for _, rule := range n.forwardRules {
		if rule.Source == src && rule.Target == n.id.ID && rule.TargetHost == host && rule.TargetPort == int(port) {
			allowed = true
			break
		}
	}
	n.forwardMu.Unlock()
	if !allowed {
		n.logf("rejected unauthorized reverse tunnel from %s", src[:8])
		return
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		n.encrypted(src, "TUNNEL_CLOSE", map[string]any{"id": id}, "")
		return
	}
	n.forwardMu.Lock()
	n.tunnels[tunnelKey(src, id)] = c
	n.forwardMu.Unlock()
	go func() { defer n.closeTunnel(src, id); n.copyTunnel(c, src, id) }()
}
func (n *node) tunnelData(src string, body map[string]any) {
	id, _ := body["id"].(string)
	encoded, _ := body["data"].(string)
	data, err := protocol.B64Decode(encoded)
	if id == "" || err != nil || len(data) > 900 {
		return
	}
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(src, id)]
	n.forwardMu.Unlock()
	if c != nil {
		_, _ = c.Write(data)
	}
}
func (n *node) tunnelClose(src string, body map[string]any) {
	id, _ := body["id"].(string)
	if id == "" {
		return
	}
	n.forwardMu.Lock()
	c := n.tunnels[tunnelKey(src, id)]
	delete(n.tunnels, tunnelKey(src, id))
	n.forwardMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// A cone relay must only scan after it has received a SYMMETRIC_BURST. Starting
// from a topology push races ahead of the symmetric peer, while retaining a
// scan after an edge disappears wastes tens of seconds probing an obsolete
// mapping.
func (n *node) cancelObsoleteSymmetricScans() {
	n.mu.RLock()
	neighbors := make(map[string]bool, len(n.neighbors))
	for id := range n.neighbors {
		neighbors[id] = true
	}
	n.mu.RUnlock()
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()
	for id, cancel := range n.symmetricScans {
		if neighbors[id] {
			continue
		}
		delete(n.symmetricScans, id)
		close(cancel)
		delete(n.symmetricSessions, id)
		delete(n.symmetricConnected, id)
		delete(n.symmetricBurstAt, id)
		delete(n.symmetricBurstSess, id)
	}
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
// buildRoutes computes the lowest-cost next hop to each reachable node.
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
			if x.id == n.id.ID && !n.usable(n.neighbors[v.id]) {
				continue
			}
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
		if p, ok := n.neighbors[d]; ok && n.usable(p) {
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
// start brings up transports, discovery, packet workers, and health loops.
func (n *node) start() error {
	if n.c.endpoint == "" {
		n.logf("detecting public UDP endpoint via STUN")
		endpoint, nat, e := n.detectEndpoint()
		if e != nil {
			return fmt.Errorf("detect external endpoint: %w", e)
		}
		n.c.endpoint = endpoint
		n.logf("public UDP endpoint detected: %s, NAT=%s", endpoint, nat)
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
		if d, ok := f.(interface{ setDebug(bool) }); ok {
			d.setDebug(n.c.debug)
		}
		if d, ok := f.(interface{ adapterLUID() uint64 }); ok {
			n.tunLUID = d.adapterLUID()
		}
		if n.c.autoTUN {
			if e := configureTUN(n.c.tun, n.c.meshIP, n.c.prefix, n.tunLUID); e != nil {
				_ = n.tun.Close()
				n.tun = nil
				return e
			}
			n.logf("TUN %s configured with %s/%d", n.c.tun, n.c.meshIP, n.c.prefix)
			if e := n.syncTUNRoutes(); e != nil {
				_ = n.tun.Close()
				n.tun = nil
				return e
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	if e := n.startPprof(); e != nil {
		return e
	}
	n.startUDPSender(ctx)
	n.startFastWorkers(ctx)
	n.startDeliverWorker(ctx)
	go n.receive(ctx)
	go n.monitorNetwork(ctx)
	go n.monitorControl(ctx)
	go n.periodic(ctx, helloInterval, n.helloAll)
	go n.periodic(ctx, pingInterval, n.pingAll)
	go n.periodic(ctx, heartbeat, func() {
		if e := n.register(); e != nil {
			n.logf("heartbeat failed: %v", e)
		}
	})
	go n.periodic(ctx, telemetryInterval, func() {
		if e := n.reportTelemetry(); e != nil {
			n.logf("telemetry failed: %v", e)
		}
	})
	go n.periodic(ctx, recoveryCheck, n.recoverNetwork)
	go n.periodic(ctx, topologyPoll, func() {
		if err := n.bootstrap(); err != nil {
			n.logf("periodic topology refresh failed: %v", err)
		}
	})
	go n.linkHealth(ctx)
	if err := n.startLANDiscovery(ctx); err != nil {
		n.logf("LAN discovery unavailable: %v", err)
	}
	go n.serveDNS(ctx)
	if n.c.statsInterval > 0 {
		go n.statsLoop(ctx, n.c.statsInterval)
	}
	if n.tun != nil {
		go n.tunLoop(ctx)
	}
	port := n.currentUDPConn().LocalAddr().(*net.UDPAddr).Port
	if err := configurePlatformNetwork(port); err != nil {
		n.logf("automatic Windows firewall integration unavailable on UDP %d: %v", port, err)
	} else if runtime.GOOS == "windows" {
		n.logf("Windows firewall rule enabled for inbound UDP %d", port)
	}
	n.helloAll()
	// Establish direct paths immediately; waiting for the first keepalive
	// interval makes a freshly started node look offline unnecessarily long.
	n.pingAll()
	go func() {
		timer := time.NewTimer(initialTelemetryDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := n.reportTelemetry(); err != nil {
				n.logf("initial telemetry failed: %v", err)
			}
		}
	}()
	n.logf("listening on %s", n.currentUDPConn().LocalAddr())
	return nil
}

// establishSymmetricTransport establishes one UDP mapping per superpeer. A
// symmetric NAT allocates a mapping per destination, so a single selected
// socket cannot serve all superpeers.
// establishSymmetricTransport opens per-relay UDP mappings for symmetric NAT.
func (n *node) establishSymmetricTransport() bool {
	// Cone (and open) NATs use the normal UDP socket.  They must not enter the
	// symmetric scan below: it intentionally creates per-superpeer sockets.
	if n.c.nat != "symmetric" {
		return true
	}

	// A long symmetric-NAT scan can outlive the coordinator's node TTL.
	// Keep the registration lease alive before the normal periodic loops are
	// started (start() blocks here until transport selection completes).
	leaseStop := make(chan struct{})
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		ticker := time.NewTicker(heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := n.register(); err != nil {
					n.logf("symmetric scan lease refresh failed: %v", err)
				}
			case <-leaseStop:
				return
			}
		}
	}()
	defer func() { close(leaseStop); <-leaseDone }()
	for attempt := 1; attempt <= symmetricBurstRetries; attempt++ {
		relays := n.symmetricRelays()
		ready := 0
		for _, relay := range relays {
			if n.symmetricTransportReady(relay.id) || n.relayLANLive(relay.id) {
				// A traffic-confirmed LAN path already serves the relay through
				// the regular socket. Probing its public endpoint from the same
				// LAN hairpins through the NAT (often unsupported) and each
				// attempt burns hundreds of source ports in the router's
				// conntrack table.
				ready++
				continue
			}
			if n.establishSymmetricTransportOnce(relay.id, &relay.peer, attempt) {
				ready++
				n.logf("symmetric NAT connected to superpeer %s", relay.id[:8])
			}
		}
		if len(relays) > 0 && ready == len(relays) {
			return true
		}
		if attempt < symmetricBurstRetries {
			n.logf("symmetric burst retry round %d/%d", attempt, symmetricBurstRetries-1)
			if err := n.bootstrap(); err != nil {
				n.logf("topology refresh before symmetric retry failed: %v", err)
			}
			time.Sleep(symmetricRetryDelay)
		}
	}
	return n.symmetricTransportCount() > 0 || n.someRelayLANLive()
}

// relayLANLive reports whether the relay currently has a traffic-confirmed
// LAN path, which makes a symmetric probe burst unnecessary: LAN traffic
// flows through the regular socket without traversing the NAT device.
func (n *node) relayLANLive(relayID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return freshLAN(n.neighbors[relayID], time.Now())
}

// someRelayLANLive reports whether at least one superpeer has a live LAN path.
func (n *node) someRelayLANLive() bool {
	now := time.Now()
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, candidate := range n.neighbors {
		if candidate.Role == "superpeer" && freshLAN(candidate, now) {
			return true
		}
	}
	return false
}

func (n *node) establishSymmetricTransportOnce(relayID string, relay *peer, attempt int) bool {
	if n.c.nat != "symmetric" {
		return true
	}
	if n.symmetricTransportReady(relayID) {
		return true
	}
	if n.relayLANLive(relayID) {
		n.logf("symmetric NAT: superpeer %s is reachable via LAN; skipping probe burst", relayID[:8])
		return true
	}
	endpoint, err := net.ResolveUDPAddr("udp", relay.Endpoint)
	if err != nil {
		n.logf("invalid superpeer endpoint: %v", err)
		return false
	}
	sessionID, err := newSymmetricSessionID()
	if err != nil {
		n.logf("create symmetric rendezvous session: %v", err)
		return false
	}
	proceed, coordinated := n.requestSymmetricScan(relayID, sessionID)
	if !proceed {
		return false
	}
	if !coordinated {
		// Old peers do not echo a session identifier in HELLO. Keep the
		// complete legacy wire format when the coordinator reports no API.
		sessionID = ""
	}

	responses := make(chan symmetricReply, symmetricBurstSize)
	sockets := make([]*net.UDPConn, 0, symmetricBurstSize)
	n.logf("symmetric NAT: probing %d UDP ports via %s (attempt %d/%d)", symmetricBurstSize, relayID[:8], attempt, symmetricBurstRetries)
	for range symmetricBurstSize {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(n.c.bind)})
		if err != nil {
			continue
		}
		burst := protocol.NewPacket("SYMMETRIC_BURST", n.id.ID, relayID, map[string]any{"session_id": sessionID})
		encoded, err := protocol.EncodePacket(burst, n.key)
		if err != nil {
			probe.Close()
			continue
		}
		if _, err = probe.WriteToUDP(encoded, endpoint); err != nil {
			probe.Close()
			continue
		}
		configureUDPSocket(probe)
		sockets = append(sockets, probe)
		go n.awaitSymmetricHello(probe, relayID, sessionID, responses)
	}

	deadline := time.NewTimer(symmetricBurstTimeout)
	defer deadline.Stop()
	var selected *net.UDPConn
	for selected == nil {
		select {
		case received := <-responses:
			selected = received.conn
			// awaitSymmetricHello reads the handshake directly from the probe
			// socket, so it does not pass through handleDatagram/touch. Mark the
			// relay live here; otherwise linkHealth immediately sees a zero
			// lastRX after a successful scan and starts the same scan again.
			n.touch(relayID, received.addr)
			ack := protocol.NewPacket("HELLO_ACK", n.id.ID, relayID, map[string]any{"session_id": sessionID})
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
	primary := n.installSymmetricConn(relayID, selected)
	if primary {
		previousEndpoint := n.c.endpoint
		if endpoint, _, err := n.detectEndpoint(); err == nil {
			n.c.endpoint = endpoint
			if endpointIPChanged(previousEndpoint, endpoint) {
				if err := n.register(); err != nil {
					n.logf("symmetric NAT endpoint update failed: %v", err)
				} else if err := n.bootstrap(); err != nil {
					n.logf("topology refresh after symmetric NAT update failed: %v", err)
				}
			}
		}
	}
	n.logf("symmetric NAT synchronized through %s on %s", relayID[:8], selected.LocalAddr())
	return true
}

func newSymmetricSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

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

// symmetricRelay is kept as a deterministic compatibility helper for callers
// that only need the preferred relay. Establishment itself uses all relays.
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

// installSymmetricConn keeps the first successful socket as the node's
// primary socket and retains every later socket for its own superpeer.
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

// rebindUDPConn drops the socket created on the previous network and creates
// a new one. On Android a wildcard-bound UDP socket can remain associated with
// the Wi-Fi Network after the default network changes to LTE; refreshing STUN
// on that socket then keeps returning the dead mapping.
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

// scanSymmetricNeighbor probes likely external ports until the peer responds.
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

// symmetricScanPorts scans ports in sparse, offset passes.  A 200-port step
// for a peer advertised on 54532 starts at 54332, continues with 54732 through
// 65532, wraps to 132, and only then begins the next pass around 54531.
//
// The advertised port is included at the end of its own pass, before the scan
// shifts the pass center down by one.
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

func symmetricScanPortPass(center, step int, visit func(port int) bool) bool {
	first := center % step
	if first < 0 {
		first += step
	}
	if first == 0 {
		first = step
	}
	last := first + (maxUDPPort-first)/step*step
	if center < 1 {
		for port := first; port <= last; port += step {
			if !visit(port) {
				return false
			}
		}
		return true
	}
	beforeCenter := center - step
	if beforeCenter >= first && !visit(beforeCenter) {
		return false
	}
	for port := center + step; port <= last; port += step {
		if !visit(port) {
			return false
		}
	}
	for port := first; port < beforeCenter; port += step {
		if !visit(port) {
			return false
		}
	}
	return visit(center)
}

func (n *node) symmetricScanCancelled(cancel chan struct{}) bool {
	select {
	case <-cancel:
		return true
	default:
		return false
	}
}

func (n *node) completeSymmetricScan(peerID, sessionID string) {
	n.symmetricMu.Lock()
	defer n.symmetricMu.Unlock()

	cancel := n.symmetricScans[peerID]
	if cancel == nil || n.symmetricSessions[peerID] != sessionID {
		// A normal HELLO_ACK does not prove that the symmetric scan succeeded.
		return
	}

	delete(n.symmetricScans, peerID)
	delete(n.symmetricSessions, peerID)
	close(cancel)
	n.symmetricConnected[peerID] = true
	n.debugf("symmetric scan completed for %s", peerID[:8])
}

func (n *node) handleSymmetricBurst(packet protocol.Packet, observed *net.UDPAddr) {
	if n.c.role != "superpeer" {
		return
	}
	n.mu.RLock()
	peer := n.neighbors[packet.Source]
	n.mu.RUnlock()
	if peer == nil || peer.NAT != "symmetric" {
		return
	}
	sessionID := payloadString(packet, "session_id")
	n.symmetricMu.Lock()
	armedSession := n.symmetricSessions[packet.Source]
	previous := n.symmetricBurstAt[packet.Source]
	previousSession := n.symmetricBurstSess[packet.Source]
	if armedSession != "" && sessionID != armedSession {
		n.symmetricMu.Unlock()
		return
	}
	if previousSession == sessionID && time.Since(previous) < 5*time.Second {
		n.symmetricMu.Unlock()
		return
	}
	n.symmetricBurstAt[packet.Source] = time.Now()
	n.symmetricBurstSess[packet.Source] = sessionID
	n.symmetricMu.Unlock()
	// A burst is optional: the control-plane event already started the scan.
	// When one arrives, use its observed mapping to refine the scan window.
	endpoint := peer.Endpoint
	if observed != nil {
		endpoint = observed.String()
	}
	// The control-plane event normally started the scan already. Restart only
	// when the burst supplies a different observed mapping that can refine it.
	refine := observed != nil && observed.String() != peer.Endpoint
	n.startSymmetricScan(packet.Source, endpoint, sessionID, refine)
}

func payloadString(packet protocol.Packet, key string) string {
	value, _ := packet.Payload[key].(string)
	return value
}

func (n *node) handleSymmetricScanEvent(peerID, sessionID, endpoint string) {
	if n.c.role != "superpeer" || peerID == "" || sessionID == "" || endpoint == "" {
		return
	}
	n.mu.RLock()
	peer := n.neighbors[peerID]
	n.mu.RUnlock()
	if peer == nil || peer.NAT != "symmetric" {
		return
	}
	// The control-plane event is the rendezvous barrier: begin scanning before
	// acknowledging it, so both peers scan concurrently. A later UDP burst can
	// refine the window but must never be required to start the scan.
	n.symmetricMu.Lock()
	if existing := n.symmetricScans[peerID]; existing != nil {
		delete(n.symmetricScans, peerID)
		delete(n.symmetricSessions, peerID)
		close(existing)
	}
	delete(n.symmetricConnected, peerID)
	n.symmetricSessions[peerID] = sessionID
	delete(n.symmetricBurstAt, peerID)
	delete(n.symmetricBurstSess, peerID)
	n.symmetricMu.Unlock()
	n.startSymmetricScan(peerID, endpoint, sessionID, true)
	err := n.request("POST", "/v1/symmetric-scan/ack", map[string]any{
		"source_node_id": peerID,
		"session_id":     sessionID,
	}, &map[string]any{})
	if err != nil {
		n.logf("symmetric scan ACK for %s failed: %v", peerID[:8], err)
	}
}

func (n *node) sendToAddress(packet protocol.Packet, address *net.UDPAddr) {
	encoded, err := protocol.EncodePacket(packet, n.key)
	if err != nil {
		return
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return
	}
	_, _ = conn.WriteToUDP(encoded, address)
}

// sendCompact emits PING/PONG in the binary keepalive format, cutting each
// keepalive from ~225 to ~70 bytes. It mirrors sendToAddress and falls back
// to the JSON envelope when the packet cannot be compact-encoded.
func (n *node) sendCompact(packet protocol.Packet, address *net.UDPAddr) {
	encoded, err := protocol.EncodeCompact(packet, n.key)
	if err != nil {
		n.sendToAddress(packet, address)
		return
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return
	}
	_, _ = conn.WriteToUDP(encoded, address)
}
func (n *node) periodic(ctx context.Context, d time.Duration, f func()) {
	// Nodes commonly start at the same time (service restart, container
	// rollout, or a laptop waking up). A small per-loop phase prevents all
	// registrations, telemetry and topology refreshes from becoming one
	// control-plane burst. Keep short health loops immediate; they are useful
	// for fast recovery and do not generate meaningful traffic by themselves.
	if d >= 10*time.Second {
		phase := d / 5
		if phase > 5*time.Second {
			phase = 5 * time.Second
		}
		var seed [2]byte
		if _, err := rand.Read(seed[:]); err == nil {
			phase = time.Duration(binary.BigEndian.Uint16(seed[:])) % (phase + 1)
		}
		if phase > 0 {
			timer := time.NewTimer(phase)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
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

// startLANDiscovery gives peers on the same broadcast domain a private
// endpoint candidate. Public STUN endpoints are not guaranteed to support
// NAT hairpinning, so two machines on one LAN must not be forced through the
// public address of their router.
// startLANDiscovery listens for nearby peers that can use a direct LAN path.
func (n *node) startLANDiscovery(ctx context.Context) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: lanDiscoveryPort})
	if err != nil {
		return err
	}
	n.lanConn = conn
	go n.lanDiscoveryLoop(ctx, conn)
	n.broadcastLANDiscovery()
	go n.lanDiscoveryBurst(ctx)
	go n.periodic(ctx, lanDiscoveryInterval, n.broadcastLANDiscovery)
	go n.periodic(ctx, lanProbeInterval, n.probeLanCandidates)
	return nil
}

// lanDiscoveryBurst repeats the broadcast a few times with an exponential
// backoff right after startup. A peer that is still bootstrapping cannot use
// discovery candidates that arrive before its topology is ready; short
// retries close that window instead of waiting a full interval.
func (n *node) lanDiscoveryBurst(ctx context.Context) {
	delay := time.Second
	for i := 0; i < lanDiscoveryBurstCount; i++ {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		n.broadcastLANDiscovery()
		delay *= 2
	}
}

// probeLanCandidates unicasts HELLO probes to the LAN addresses peers
// advertised through the coordinator. Broadcast discovery cannot cross a
// router, so this is the only way to find neighbors in an adjacent subnet of
// the same physical network (cascaded routers). The per-peer interval and
// fresh-LAN checks keep the cost at a few small datagrams per tick; the
// candidate set is re-checked on a fixed schedule instead of waiting for a
// topology push, so candidates also work in a fully stable network.
func (n *node) probeLanCandidates() {
	type probe struct {
		id   string
		addr *net.UDPAddr
	}
	now := time.Now()
	n.mu.Lock()
	probes := make([]probe, 0, 4)
	for id, p := range n.neighbors {
		if len(p.LANAddrs) == 0 || now.Sub(p.lastLANProbe) < lanProbeInterval || freshLAN(p, now) {
			continue
		}
		p.lastLANProbe = now
		for _, raw := range p.LANAddrs {
			if len(probes) >= lanProbeMaxAddrs {
				break
			}
			addr, err := net.ResolveUDPAddr("udp4", raw)
			if err != nil || addr.IP == nil {
				continue
			}
			p.lastLAN = copyUDPAddr(addr)
			probes = append(probes, probe{id: id, addr: copyUDPAddr(addr)})
		}
	}
	n.mu.Unlock()
	for _, pr := range probes {
		n.debugf("LAN probe to %s at %s", pr.id[:8], pr.addr)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, pr.id, map[string]any{"public_key": n.id.Public}), pr.addr)
	}
}

func (n *node) broadcastLANDiscovery() {
	n.mu.RLock()
	if n.lanConn == nil {
		n.mu.RUnlock()
		return
	}
	conn := n.lanConn
	n.mu.RUnlock()
	if !n.meshHasOtherNodes() {
		// A lone node has nobody to discover: the broadcast would be noise.
		n.debugf("LAN discovery skipped: no other node in the mesh")
		return
	}
	port := n.currentUDPConn().LocalAddr().(*net.UDPAddr).Port
	p := protocol.NewPacket("LAN_DISCOVERY", n.id.ID, "", map[string]any{"udp_port": port})
	b, err := protocol.EncodePacket(p, n.key)
	if err != nil {
		return
	}
	// The limited broadcast alone finds peers unreliably: multi-homed hosts
	// send it out of the default-route interface only, and some Wi-Fi
	// drivers or APs drop it entirely. Every local subnet therefore also
	// receives a directed broadcast (192.168.1.255 style), which the routing
	// table delivers through the interface that actually owns the subnet.
	targets := append([]net.IP{net.IPv4bcast}, n.subnetBroadcastAddrs()...)
	for _, ip := range targets {
		if _, err = conn.WriteToUDP(b, &net.UDPAddr{IP: ip, Port: lanDiscoveryPort}); err != nil {
			n.debugf("LAN discovery broadcast to %s failed: %v", ip, err)
		}
	}
}

// subnetBroadcastAddrs returns the directed broadcast address of every
// physical local subnet. Unlike 255.255.255.255, a directed broadcast
// follows the routing table and leaves through the interface that owns the
// subnet, which makes LAN discovery work on routers and multi-NIC hosts.
func (n *node) subnetBroadcastAddrs() []net.IP {
	subnets := n.localSubnets()
	out := make([]net.IP, 0, len(subnets))
	seen := map[uint32]bool{}
	for _, subnet := range subnets {
		ip, ok := broadcastForPrefix(subnet)
		if !ok {
			continue
		}
		key := binary.BigEndian.Uint32(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out
}

// broadcastForPrefix returns the directed broadcast address of a prefix:
// the masked network address with all host bits set. /31 and /32 have no
// broadcast address and /0 is the default route, so they report false.
func broadcastForPrefix(subnet netip.Prefix) (net.IP, bool) {
	if !subnet.Addr().Is4() || subnet.Bits() <= 0 || subnet.Bits() >= 31 {
		return nil, false
	}
	raw := subnet.Masked().Addr().As4()
	addr := binary.BigEndian.Uint32(raw[:])
	addr |= 0xffffffff >> subnet.Bits()
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).To4(), true
}

func (n *node) lanDiscoveryLoop(ctx context.Context, conn *net.UDPConn) {
	buffer := make([]byte, protocol.MaxDatagramSize)
	for {
		length, address, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			n.debugf("LAN discovery receive failed: %v", err)
			continue
		}
		packet, err := protocol.DecodePacket(buffer[:length], n.key)
		if err != nil || packet.Type != "LAN_DISCOVERY" || packet.Source == n.id.ID {
			continue
		}
		var payload struct {
			Port int `json:"udp_port"`
		}
		raw, err := json.Marshal(packet.Payload)
		if err != nil || json.Unmarshal(raw, &payload) != nil || payload.Port < 1 || payload.Port > 65535 {
			continue
		}
		candidate := copyUDPAddr(&net.UDPAddr{IP: address.IP, Port: payload.Port})
		n.mu.Lock()
		peer := n.neighbors[packet.Source]
		if peer != nil {
			// Candidate only: lastLANRX is set by touch() once traffic actually
			// arrives from this address, so an unreachable candidate (LAN
			// segmentation, AP isolation) never suppresses the public path.
			peer.lastLAN = candidate
			peer.last = candidate
		} else {
			// The peer is not installed yet (still bootstrapping, or this node
			// just started). Buffer the candidate so it survives until
			// applyTopology creates the peer; dropping it used to leave the
			// NAT-hairpin public path as the only option.
			if n.pendingLAN == nil {
				n.pendingLAN = map[string]*net.UDPAddr{}
			}
			n.pendingLAN[packet.Source] = candidate
		}
		n.mu.Unlock()
		n.debugf("LAN endpoint candidate for %s: %s", packet.Source[:8], candidate)
		n.sendToAddress(protocol.NewPacket("HELLO", n.id.ID, packet.Source, map[string]any{"public_key": n.id.Public}), candidate)
	}
}

func (n *node) resetTransportState() {
	n.mu.Lock()
	for _, peer := range n.neighbors {
		peer.last = nil
		peer.lastRX = time.Time{}
		peer.lastLAN = nil
		peer.lastLANRX = time.Time{}
		peer.lastPathLAN = false
		peer.lastLANProbe = time.Time{}
		peer.up = false
	}
	n.pendingLAN = map[string]*net.UDPAddr{}
	n.mu.Unlock()
	current := n.currentUDPConn()
	n.symmetricConnMu.Lock()
	for id, conn := range n.symmetricConns {
		if conn != nil && conn != current {
			_ = conn.Close()
		}
		delete(n.symmetricConns, id)
	}
	n.symmetricConns = map[string]*net.UDPConn{}
	n.symmetricConnMu.Unlock()
	n.symmetricMu.Lock()
	n.symmetricReady = false
	for id, cancel := range n.symmetricScans {
		delete(n.symmetricScans, id)
		close(cancel)
	}
	n.symmetricSessions = map[string]string{}
	n.symmetricAckWaiters = map[string]chan struct{}{}
	n.symmetricConnected = map[string]bool{}
	n.symmetricBurstAt = map[string]time.Time{}
	n.symmetricBurstSess = map[string]string{}
	n.symmetricMu.Unlock()
}

// restoreTUNNetwork repairs host-side state that a mobile network switch can
// discard. The installed-route cache is cleared because routes may be gone in
// the kernel even though they are still present in the cache.
func (n *node) restoreTUNNetwork() error {
	if n.tun == nil || !n.c.autoTUN {
		return nil
	}
	if err := configureTUN(n.c.tun, n.c.meshIP, n.c.prefix, n.tunLUID); err != nil {
		return err
	}
	return n.forceTUNRouteSync()
}

func (n *node) forceTUNRouteSync() error {
	n.routeMu.Lock()
	n.installedRoutes = map[string]bool{}
	n.routeMu.Unlock()
	return n.syncTUNRoutes()
}

// resetSymmetricRelay drops only one superpeer mapping. It is used when a
// single edge dies, so the remaining symmetric links stay usable while this
// relay gets a fresh rendezvous and port scan.
func (n *node) resetSymmetricRelay(relayID string) {
	n.symmetricConnMu.Lock()
	if conn := n.symmetricConns[relayID]; conn != nil {
		_ = conn.Close()
	}
	delete(n.symmetricConns, relayID)
	n.symmetricConnMu.Unlock()

	n.symmetricMu.Lock()
	if cancel := n.symmetricScans[relayID]; cancel != nil {
		delete(n.symmetricScans, relayID)
		close(cancel)
	}
	delete(n.symmetricSessions, relayID)
	delete(n.symmetricConnected, relayID)
	delete(n.symmetricBurstAt, relayID)
	delete(n.symmetricBurstSess, relayID)
	n.symmetricMu.Unlock()
}

const (
	edgeRetryAttempts = 3
	edgeRetryDelay    = 2 * time.Second
)

// retryDeadEdge keeps retrying an individual failed edge. Global network
// recovery is intentionally conservative and only runs when every neighbor is
// stale, so it cannot be the mechanism that revives one dead edge in an
// otherwise healthy mesh.
func (n *node) retryDeadEdge(id string, snapshot peer) {
	n.edgeRetryMu.Lock()
	if n.edgeRetries == nil {
		n.edgeRetries = map[string]bool{}
	}
	if n.edgeRetries[id] {
		n.edgeRetryMu.Unlock()
		return
	}
	n.edgeRetries[id] = true
	n.edgeRetryMu.Unlock()

	go func() {
		defer func() {
			n.edgeRetryMu.Lock()
			delete(n.edgeRetries, id)
			n.edgeRetryMu.Unlock()
		}()

		if n.c.nat == "symmetric" && snapshot.Role == "superpeer" {
			if n.relayLANLive(id) {
				// The LAN path keeps the edge alive; a public probe burst would
				// only hairpin through the NAT and flood conntrack again.
				return
			}
			n.resetSymmetricRelay(id)
			for attempt := 1; attempt <= edgeRetryAttempts; attempt++ {
				if n.establishSymmetricTransportOnce(id, &snapshot, attempt) {
					return
				}
				if attempt < edgeRetryAttempts {
					time.Sleep(edgeRetryDelay)
				}
			}
			return
		}

		for attempt := 1; attempt <= edgeRetryAttempts; attempt++ {
			n.mu.RLock()
			current := n.neighbors[id]
			if current != nil {
				copy := *current
				if n.usable(current) {
					n.mu.RUnlock()
					return
				}
				snapshot = copy
			}
			n.mu.RUnlock()
			if current == nil {
				return
			}
			// HELLO is deliberately sent on every retry, even when the cached
			// observed address is stale: sendHello also tries the endpoint from
			// the latest topology snapshot. This is what reopens a lost NAT
			// mapping and causes the peer to refresh its address on both sides.
			n.sendHello(snapshot)
			if attempt < edgeRetryAttempts {
				time.Sleep(edgeRetryDelay)
			}
		}
	}()
}

func (n *node) sendHello(p peer) {
	packet := protocol.NewPacket("HELLO", n.id.ID, p.ID, map[string]any{"public_key": n.id.Public})
	if observed, ok := p.last.(*net.UDPAddr); ok {
		n.sendToAddress(packet, observed)
	}
	// Edge retries are the recovery path: always also try the declared public
	// endpoint. LAN preference and sameNAT are hints, never a reason to
	// withhold a candidate here — the LAN segment may be unreachable even when
	// both nodes share one external IP.
	if address, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
		n.sendToAddress(packet, address)
	}
}

func (n *node) deferRecovery(err error, action string) {
	n.recoveryFails++
	backoff := recoveryMinBackoff
	for i := 1; i < n.recoveryFails && backoff < recoveryMaxBackoff; i++ {
		backoff *= 2
	}
	if backoff > recoveryMaxBackoff {
		backoff = recoveryMaxBackoff
	}
	n.recoveryNext = time.Now().Add(backoff)
	n.logf("%s: %v; retrying in %s", action, err, backoff)
}

// recoverNetwork rebuilds local connectivity after all neighbor paths go stale.
func (n *node) recoverNetwork() {
	n.mu.RLock()
	stale := len(n.neighbors) > 0
	for _, peer := range n.neighbors {
		// A single offline neighbor is normal in a mesh. Recovery of the
		// local NAT mapping is only justified when every observed neighbor is
		// stale; otherwise an unrelated peer can repeatedly disrupt healthy
		// traffic on this node.
		if (!peer.lastRX.IsZero() && time.Since(peer.lastRX) < linkTimeout) ||
			(peer.lastRX.IsZero() && time.Since(peer.discovered) < linkGrace) {
			stale = false
			break
		}
	}
	n.mu.RUnlock()
	if !stale || !n.recoveryMu.TryLock() {
		return
	}
	defer n.recoveryMu.Unlock()
	if time.Now().Before(n.recoveryNext) {
		return
	}
	n.logf("network link stale; refreshing STUN endpoint and topology")
	if err := n.rebindUDPConn(); err != nil {
		n.deferRecovery(err, "UDP socket recovery failed")
		return
	}
	n.resetTransportState()
	if err := n.restoreTUNNetwork(); err != nil {
		n.deferRecovery(err, "TUN network restore failed")
		return
	}
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		n.deferRecovery(err, "STUN recovery failed")
		return
	}
	previousEndpoint := n.c.endpoint
	ipChanged := endpointIPChanged(previousEndpoint, endpoint)
	n.c.endpoint = endpoint
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	if ipChanged {
		if err := n.register(); err != nil {
			n.deferRecovery(err, "re-register after network loss failed")
			return
		}
		if err := n.bootstrap(); err != nil {
			n.deferRecovery(err, "topology refresh after network loss failed")
			return
		}
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.deferRecovery(errors.New("symmetric handshake did not complete"), "symmetric transport recovery failed")
		return
	}
	n.recoveryFails = 0
	n.recoveryNext = time.Time{}
	n.helloAll()
	n.pingAll()
}

// networkFingerprint summarizes the currently up IPv4 interface configuration.
// It deliberately excludes the mesh TUN: configuring the TUN during recovery
// must not look like a roaming event and trigger another recovery.
func (n *node) networkFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		n.debugf("network fingerprint unavailable: %v", err)
		return ""
	}
	return fingerprintInterfaces(ifaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }, n.c.tun)
}

// fingerprintInterfaces joins per-interface address lists into one string.
// Sorting makes the result independent of enumeration order, loopback and
// interfaces without an IPv4 address are skipped, so plain carrier-grade NAT
// rebinds that keep the interface set stable do not spam recovery.
func fingerprintInterfaces(ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error), skip string) string {
	parts := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == skip {
			continue
		}
		list, err := addrs(iface)
		if err != nil {
			continue
		}
		addresses := make([]string, 0, len(list))
		for _, address := range list {
			prefix, ok := address.(*net.IPNet)
			if !ok || prefix.IP.To4() == nil {
				continue
			}
			ones, _ := prefix.Mask.Size()
			addresses = append(addresses, prefix.IP.String()+"/"+strconv.Itoa(ones))
		}
		if len(addresses) == 0 {
			continue
		}
		sort.Strings(addresses)
		parts = append(parts, iface.Name+"="+strings.Join(addresses, ","))
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// monitorNetwork polls the interface table and reacts to Wi-Fi <-> LTE style
// switches within a few seconds. Waiting for traffic failures instead leaves a
// mobile node blind for 30-90 s: half-open control connections and UDP sockets
// pinned to the previous network keep looking alive far too long.
func (n *node) monitorNetwork(ctx context.Context) {
	previous := n.networkFingerprint()
	ticker := time.NewTicker(networkCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		current := n.networkFingerprint()
		// An empty fingerprint means "cannot tell" (total loss, enumeration
		// failure); only a real observed change triggers roaming recovery.
		if current == "" || current == previous {
			continue
		}
		previous = current
		n.logf("network change detected: %s", current)
		n.handleNetworkChange()
	}
}

// handleNetworkChange starts a roaming refresh: a new network invalidates the
// UDP socket, all cached peer paths and often the control connection.
func (n *node) handleNetworkChange() {
	// A fresh network event restarts recovery from scratch. Backoff collected
	// while the old network was settling must not delay recovery now that the
	// new network is up. TryLock: when a recovery pass is already running it
	// will pick the new network up on its own.
	if n.recoveryMu.TryLock() {
		n.recoveryFails = 0
		n.recoveryNext = time.Time{}
		n.recoveryMu.Unlock()
	}
	// The control WebSocket rides on the previous network and may stay
	// half-open for minutes. Close it so the next heartbeat reconnects over
	// the new network immediately; readControl will also notice and poke.
	n.controlMu.Lock()
	if n.control != nil {
		_ = n.control.Close()
		n.control = nil
	}
	n.controlMu.Unlock()
	// Coalesce interface flapping into one refresh.
	now := time.Now().Unix()
	last := n.roamRefreshAt.Load()
	if last != 0 && time.Since(time.Unix(last, 0)) < roamRefreshMinGap {
		return
	}
	if !n.roamRefreshAt.CompareAndSwap(last, now) {
		return
	}
	go n.roamRefresh(1)
}

// roamRefresh rebuilds the whole transport after a network switch. Unlike the
// post-reconnect endpoint check it never trusts "the external endpoint looks
// the same": on Android the old socket can stay pinned to the dead Wi-Fi
// network while STUN still answers through it. The socket is always rebound
// and every cached peer path is dropped.
func (n *node) roamRefresh(attempt int) {
	if !n.recoveryMu.TryLock() {
		// recoverNetwork or a newer roam pass is in flight; that pass already
		// observes the new network.
		return
	}
	defer n.recoveryMu.Unlock()
	retry := func(stage string, err error) {
		n.logf("network change: %s: %v", stage, err)
		if attempt < endpointRefreshRetries {
			time.AfterFunc(endpointRefreshRetryDelay, func() { n.roamRefresh(attempt + 1) })
			return
		}
		n.logf("network change: giving up for now; keepalive recovery stays armed")
	}
	if err := n.rebindUDPConn(); err != nil {
		retry("UDP rebind failed", err)
		return
	}
	endpoint, nat, err := n.detectEndpoint()
	if err != nil {
		// DNS and STUN are often unusable for the first seconds after a radio
		// transition; the retries below ride them out.
		retry("STUN check failed", err)
		return
	}
	if endpoint != n.c.endpoint {
		n.logf("network change: UDP endpoint changed %s -> %s", n.c.endpoint, endpoint)
		n.c.endpoint = endpoint
	}
	if n.requestedNAT == "auto" {
		n.c.nat = nat
	}
	// Every peer.last entry and every per-superpeer socket belongs to the old
	// NAT mapping. Drop them before rebuilding; keeping them made a Wi-Fi ->
	// LTE transition keep stale symmetric state and never start a new scan.
	n.resetTransportState()
	if err := n.restoreTUNNetwork(); err != nil {
		n.logf("network change: TUN network restore failed: %v", err)
	}
	// The heartbeat also publishes the fresh endpoint to the coordinator.
	if err := n.register(); err != nil {
		retry("re-register failed", err)
		return
	}
	if err := n.bootstrap(); err != nil {
		retry("topology refresh failed", err)
		return
	}
	if n.c.nat == "symmetric" && !n.establishSymmetricTransport() {
		n.logf("network change: symmetric handshake did not complete; link health will retry")
	}
	n.helloAll()
	n.pingAll()
}

// monitorControl force-closes a control WebSocket that stopped receiving.
// A network switch usually leaves the old TCP connection half-open instead of
// sending a RST: writes appear to succeed, no reply ever arrives, and without
// this watchdog the node waits for a request timeout before even trying to
// reconnect. Topology pushes and symmetric-scan events are lost meanwhile.
func (n *node) monitorControl(ctx context.Context) {
	ticker := time.NewTicker(controlCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		n.controlMu.Lock()
		connected := n.control != nil
		n.controlMu.Unlock()
		if !connected {
			continue
		}
		if time.Since(time.Unix(0, n.controlRxAt.Load())) < controlStaleTimeout {
			continue
		}
		n.logf("control channel silent for %s; forcing reconnect", controlStaleTimeout)
		n.controlMu.Lock()
		if n.control != nil {
			_ = n.control.Close()
			n.control = nil
		}
		n.controlMu.Unlock()
	}
}

func (n *node) detectEndpoint() (string, string, error) {
	n.udpReadMu.Lock()
	defer n.udpReadMu.Unlock()
	return stunEndpoint(n.currentUDPConn(), n.handleDatagram, n.c.bootstrapDNS...)
}

func (n *node) helloAll() {
	n.mu.RLock()
	type helloTarget struct {
		id           string
		observed     *net.UDPAddr
		declared     string
		skipDeclared bool
	}
	targets := make([]helloTarget, 0, len(n.neighbors))
	for id, peer := range n.neighbors {
		// PING/PONG already maintains healthy paths and learns rebinding.
		// HELLO is still sent on startup, to stale peers and by edge retries.
		if n.usable(peer) {
			continue
		}
		target := helloTarget{id: id, declared: peer.Endpoint}
		if address, ok := peer.last.(*net.UDPAddr); ok {
			target.observed = &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
		}
		if freshLAN(peer, time.Now()) && n.sameNAT(peer) {
			// The LAN path is confirmed working (traffic received) and both
			// nodes share one external IP: a duplicate HELLO to the declared
			// public endpoint would only hairpin through the NAT device.
			target.skipDeclared = true
		}
		targets = append(targets, target)
	}
	n.mu.RUnlock()
	for _, target := range targets {
		packet := protocol.NewPacket("HELLO", n.id.ID, target.id, map[string]any{"public_key": n.id.Public})
		if target.observed != nil {
			n.sendToAddress(packet, target.observed)
		}
		if address, err := net.ResolveUDPAddr("udp", target.declared); err == nil &&
			!target.skipDeclared &&
			(target.observed == nil || address.String() != target.observed.String()) {
			n.sendToAddress(packet, address)
		}
	}
}
func (n *node) pingAll() {
	now := time.Now()
	n.mu.RLock()
	targets := make([]pingTarget, 0, len(n.neighbors))
	for id, peer := range n.neighbors {
		target := pingTarget{id: id, endpoint: peer.Endpoint}
		if observed, ok := peer.last.(*net.UDPAddr); ok {
			target.observed = &net.UDPAddr{IP: append(net.IP(nil), observed.IP...), Port: observed.Port, Zone: observed.Zone}
		}
		if lan := peer.lastLAN; lan != nil && !freshLAN(peer, now) {
			// Unconfirmed LAN candidate: keepalives double as LAN probes so a
			// lost broadcast or HELLO costs one keepalive interval instead of
			// the full 30-second probe round. When the LAN path is already
			// traffic-confirmed, observed is the LAN address and no duplicate
			// datagram is sent.
			target.lan = copyUDPAddr(lan)
		}
		targets = append(targets, target)
	}
	n.mu.RUnlock()
	n.pingMu.Lock()
	prunePings(n.pings, now.Add(-linkTimeout))
	n.pingMu.Unlock()
	for _, target := range targets {
		p := protocol.NewPacket("PING", n.id.ID, target.id, map[string]any{})
		if target.lan != nil && (target.observed == nil || target.lan.String() != target.observed.String()) {
			n.sendDirect(p, "", target.lan)
		}
		if !n.sendDirect(p, target.endpoint, target.observed) {
			// Do not wait for the next linkHealth tick when the socket cannot
			// even send the probe. This used to leave a dead edge without any
			// retry until another, unrelated state transition occurred.
			n.mu.RLock()
			current := n.neighbors[target.id]
			var snapshot peer
			if current != nil {
				snapshot = *current
			}
			n.mu.RUnlock()
			if current != nil {
				n.retryDeadEdge(target.id, snapshot)
			}
			continue
		}
		n.pingMu.Lock()
		n.pings[p.ID] = pingProbe{sent: now, peerID: target.id}
		n.pingMu.Unlock()
	}
}

type pingTarget struct {
	id       string
	endpoint string
	observed *net.UDPAddr
	lan      *net.UDPAddr // unconfirmed LAN candidate to re-probe
}

// sendDirect bypasses mesh routing. Keepalive RTT is a measurement of a
// physical neighbor link, not of a potentially changing multi-hop route.
func (n *node) sendDirect(packet protocol.Packet, endpoint string, observed *net.UDPAddr) bool {
	address := observed
	if address == nil {
		var err error
		address, err = net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return false
		}
	}
	// Keepalives use the ~70-byte binary format; anything else (or a compact
	// encoding failure) falls back to the JSON envelope.
	encoded, err := protocol.EncodeCompact(packet, n.key)
	if err != nil {
		if encoded, err = protocol.EncodePacket(packet, n.key); err != nil {
			return false
		}
	}
	conn := n.connForPeer(packet.Destination)
	if conn == nil {
		return false
	}
	_, err = conn.WriteToUDP(encoded, address)
	return err == nil
}

// PONG removes its matching entry, but offline peers never answer. Bound the
// bookkeeping for those peers so a long-running node does not accumulate one
// ping timestamp per keepalive interval forever.
func prunePings(pings map[string]pingProbe, before time.Time) {
	for id, probe := range pings {
		if probe.sent.Before(before) {
			delete(pings, id)
		}
	}
}

// telemetryKeepalive bounds how long a coordinator may consider link metrics
// fresh when nothing changes. It must stay below the server's 45-second
// unknown-state threshold so idle networks keep their topology ranking even
// on older coordinators without piggybacked register links.
const telemetryKeepalive = 40 * time.Second

// currentLinks snapshots the neighbor observations reported to the coordinator.
// ViaLAN reflects where the most recent datagram from the peer actually came
// from: a private/local source address means the traffic stayed inside the
// LAN, a public source means it crossed the internet (or NAT hairpin, which
// also leaves the LAN segment through the NAT device). No holdover: the last
// packet decides.
func (n *node) currentLinks() []protocol.LinkMeasurement {
	n.mu.RLock()
	links := make([]protocol.LinkMeasurement, 0, len(n.neighbors))
	for id, p := range n.neighbors {
		links = append(links, protocol.LinkMeasurement{PeerID: id, RTTMS: p.rttMS, Up: !p.lastRX.IsZero() && time.Since(p.lastRX) < linkTimeout, ViaLAN: p.lastPathLAN})
	}
	n.mu.RUnlock()
	return links
}

// reportTelemetry sends link measurements only when they changed (link set,
// up/down state, or a meaningful RTT shift) or when the keepalive window
// elapsed. In a stable network this removes nearly all telemetry traffic;
// any change is still reported within one telemetryInterval, so monitoring
// responsiveness is unchanged. Fresh RTT for every link also arrives with
// each register heartbeat.
// reportTelemetry sends current link health to the coordinator when needed.
func (n *node) reportTelemetry() error {
	links := n.currentLinks()
	n.telemetryMu.Lock()
	send := telemetryChanged(n.lastTelemetryLinks, links) || time.Since(n.lastTelemetrySent) >= telemetryKeepalive
	if send {
		n.lastTelemetryLinks = links
		n.lastTelemetrySent = time.Now()
	}
	n.telemetryMu.Unlock()
	if !send {
		return nil
	}
	return n.request("POST", "/v1/telemetry", map[string]any{"node_id": n.id.ID, "links": links}, &map[string]any{})
}

// telemetryChanged reports whether the new measurements differ from the last
// sent snapshot enough to justify a report. RTT jitter within 30% and 3 ms is
// deliberately not reported: the coordinator smooths RTT with an EMA and a
// fresh exact value arrives with every register heartbeat anyway.
func telemetryChanged(sent, links []protocol.LinkMeasurement) bool {
	if len(sent) != len(links) {
		return true
	}
	previous := make(map[string]protocol.LinkMeasurement, len(sent))
	for _, l := range sent {
		previous[l.PeerID] = l
	}
	for _, l := range links {
		old, ok := previous[l.PeerID]
		if !ok || old.Up != l.Up || old.ViaLAN != l.ViaLAN || rttDrifted(old.RTTMS, l.RTTMS) {
			return true
		}
	}
	return false
}

func rttDrifted(prev, next float64) bool {
	if prev == 0 || next == 0 {
		return prev != next
	}
	diff := math.Abs(prev - next)
	return diff > 3 && diff > 0.3*math.Max(prev, next)
}
func (n *node) usable(p *peer) bool {
	// A topology entry is only a candidate endpoint. Do not report or route
	// through it until this node has actually received traffic from the peer.
	// Treating a zero lastRX as usable made one side show link up immediately
	// while the other side was still establishing the UDP path.
	return p != nil && !p.lastRX.IsZero() && time.Since(p.lastRX) < linkTimeout
}
func (n *node) send(p protocol.Packet) bool {
	hop, q := n.nextHop(p.Destination)
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
	_, e = n.connForPeer(hop).WriteToUDP(b, a.(*net.UDPAddr))
	return e == nil
}

// nextHop selects a cached or newly computed route for a destination.
func (n *node) nextHop(destination string) (string, *peer) {
	// Routes can change while packets are in flight; validate a cached peer before using it.
	n.mu.RLock()
	hop := n.routes[destination]
	previousHop := hop
	peer := n.neighbors[hop]
	if n.usable(peer) {
		n.mu.RUnlock()
		return hop, peer
	}

	adjacency := map[string][]qitem{}
	// Without a usable cached hop every data packet would re-run Dijkstra
	// here. During an outage with traffic flowing that is a CPU storm on a
	// mutex-held path; bound full recomputations to a few per second.
	if last := n.routeRecompute.Load(); time.Since(time.Unix(0, last)) < 250*time.Millisecond {
		n.mu.RUnlock()
		return "", nil
	}
	n.routeRecompute.Store(time.Now().UnixNano())
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
	if previousHop != hop {
		n.logf("route failover %s -> %s", destination[:8], hop[:8])
	}
	return hop, peer
}
func (n *node) startFastWorkers(ctx context.Context) {
	workers := n.c.fastWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		workers = min(workers, 2)
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

func (n *node) startDeliverWorker(ctx context.Context) {
	workers := n.c.deliverWorkers
	if workers <= 0 {
		// A TUN device is a single file descriptor; one default writer avoids scheduler and kernel-lock contention.
		workers = 1
	}
	workers = max(1, min(workers, 16))
	n.deliverQueues = make([]chan deliverFrame, workers)
	n.deliverPool.New = func() any { return make([]byte, maxTUN) }
	for i := range n.deliverQueues {
		queue := make(chan deliverFrame, fastQueueSize/workers)
		n.deliverQueues[i] = queue
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case frame := <-queue:
					n.deliver(frame.source, frame.data)
					n.deliverPool.Put(frame.data[:maxTUN])
					// Keep per-socket/TUN ordering while draining work already queued.
					// This avoids returning to select (and an unnecessary scheduler
					// decision) for every packet during a receive burst.
					for i := 0; i < 15; i++ {
						select {
						case frame := <-queue:
							n.deliver(frame.source, frame.data)
							n.deliverPool.Put(frame.data[:maxTUN])
						default:
							i = 15
						}
					}
				}
			}
		}()
	}
}

func (n *node) enqueueDeliver(source string, data []byte) {
	if len(n.deliverQueues) == 0 || len(data) < 20 || len(data) > maxTUN {
		n.stats.deliveryDrops.Add(1)
		return
	}
	// Keep packets from one IPv4 flow on one worker. This permits parallel TUN
	// writes without reordering TCP/UDP packets within a flow.
	flow := uint32(data[9])
	for _, b := range data[12:20] {
		flow = flow*16777619 ^ uint32(b)
	}
	ihl := int(data[0]&15) * 4
	if ihl >= 20 && len(data) >= ihl+4 && (data[9] == 6 || data[9] == 17) {
		for _, b := range data[ihl : ihl+4] {
			flow = flow*16777619 ^ uint32(b)
		}
	}
	queue := n.deliverQueues[int(flow%uint32(len(n.deliverQueues)))]
	owned := n.deliverPool.Get().([]byte)[:len(data)]
	copy(owned, data)
	select {
	case queue <- deliverFrame{source: source, data: owned}:
	default:
		n.deliverPool.Put(owned[:maxTUN])
		n.stats.deliveryDrops.Add(1)
		n.debugf("drop IP packet from %s: TUN queue full", source[:8])
	}
}

func (n *node) deliverQueueUsage() (length, capacity int) {
	for _, queue := range n.deliverQueues {
		length += len(queue)
		capacity += cap(queue)
	}
	return
}

func (n *node) startPprof() error {
	if n.c.pprofListen == "" {
		return nil
	}
	// Enable contention profiles only for diagnostic runs. These profiles are
	// empty by default and are intentionally not enabled in normal operation.
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
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
			rxDrops := current.rxQueueDrops - previous.rxQueueDrops
			txDrops := current.txQueueDrops - previous.txQueueDrops
			tunDrops := current.deliveryDrops - previous.deliveryDrops
			controlRxPackets := current.controlRxPackets - previous.controlRxPackets
			controlRxBytes := current.controlRxBytes - previous.controlRxBytes
			controlTxPackets := current.controlTxPackets - previous.controlTxPackets
			controlTxBytes := current.controlTxBytes - previous.controlTxBytes
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			seconds := interval.Seconds()
			deliverLength, deliverCapacity := n.deliverQueueUsage()
			n.logf("stats %s: data rx=%.0f pps %.2f Mbps tx=%.0f pps %.2f Mbps control rx=%.0f pps %.2f Mbps tx=%.0f pps %.2f Mbps tun=%.0f pps queues=%d/%d,%d/%d drops=%d/%d udpTxQueue=%d/%d rxDrops=%d txDrops=%d heap=%.1f MiB goroutines=%d",
				interval, float64(rxPackets)/seconds, float64(rxBytes*8)/seconds/1e6,
				float64(txPackets)/seconds, float64(txBytes*8)/seconds/1e6,
				float64(controlRxPackets)/seconds, float64(controlRxBytes*8)/seconds/1e6,
				float64(controlTxPackets)/seconds, float64(controlTxBytes*8)/seconds/1e6,
				float64(current.deliveredPackets-previous.deliveredPackets)/seconds, len(n.fastQueue), cap(n.fastQueue), deliverLength, deliverCapacity, drops, tunDrops, len(n.udpSendQueue), cap(n.udpSendQueue), rxDrops, txDrops,
				float64(mem.HeapAlloc)/(1024*1024), runtime.NumGoroutine())
			previous = current
		}
	}
}

type fastStatsSnapshot struct {
	receivedPackets, receivedBytes   uint64
	queueDrops                       uint64
	rxQueueDrops, txQueueDrops       uint64
	sentPackets, sentBytes           uint64
	deliveredPackets, deliveredBytes uint64
	deliveryDrops                    uint64
	controlRxPackets, controlRxBytes uint64
	controlTxPackets, controlTxBytes uint64
}

func (n *node) fastStatsSnapshot() fastStatsSnapshot {
	return fastStatsSnapshot{
		receivedPackets: n.stats.receivedPackets.Load(), receivedBytes: n.stats.receivedBytes.Load(),
		queueDrops: n.stats.queueDrops.Load(), sentPackets: n.stats.sentPackets.Load(), sentBytes: n.stats.sentBytes.Load(),
		rxQueueDrops: n.stats.rxQueueDrops.Load(), txQueueDrops: n.stats.txQueueDrops.Load(),
		deliveredPackets: n.stats.deliveredPackets.Load(), deliveredBytes: n.stats.deliveredBytes.Load(), deliveryDrops: n.stats.deliveryDrops.Load(),
		controlRxPackets: n.stats.controlRxPackets.Load(), controlRxBytes: n.stats.controlRxBytes.Load(), controlTxPackets: n.stats.controlTxPackets.Load(), controlTxBytes: n.stats.controlTxBytes.Load(),
	}
}

func (n *node) enqueueFast(data []byte, addr *net.UDPAddr) {
	n.stats.receivedPackets.Add(1)
	n.stats.receivedBytes.Add(uint64(len(data) + 28))
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
		n.stats.rxQueueDrops.Add(1)
		n.debugf("drop fast frame from %s: worker queue full", addr)
	}
}

// receive starts readers for every active UDP socket.
func (n *node) receive(ctx context.Context) {
	n.receiveMu.Lock()
	n.receiveCtx = ctx
	n.receiveStarted = true
	conns := n.transportConns()
	for _, conn := range conns {
		if _, exists := n.receiveSockets[conn]; exists {
			continue
		}
		n.receiveSockets[conn] = struct{}{}
		n.receiveWG.Add(1)
		go n.receiveSocket(ctx, conn)
	}
	n.receiveMu.Unlock()
	<-ctx.Done()
	n.receiveWG.Wait()
	close(n.fastQueue)
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

// handleDatagram authenticates and dispatches one received UDP packet.
func (n *node) handleDatagram(datagram []byte, address *net.UDPAddr) {
	if len(datagram) >= len(fastMagicBytes) && bytes.Equal(datagram[:len(fastMagicBytes)], fastMagicBytes) {
		n.enqueueFast(datagram, address)
		return
	}
	n.stats.controlRxPackets.Add(1)
	n.stats.controlRxBytes.Add(uint64(len(datagram) + 28)) // IPv4 + UDP overhead.
	var p protocol.Packet
	var e error
	if protocol.IsCompact(datagram) {
		p, e = protocol.DecodeCompact(datagram, n.key)
	} else {
		p, e = protocol.DecodePacket(datagram, n.key)
	}
	if e != nil || !n.remember(p.ID) {
		return
	}
	compact := protocol.IsCompact(datagram)
	if p.Destination == n.id.ID && confirmsDirectPath(p.Type, p.TTL) {
		n.touch(p.Source, address)
	}
	if p.Destination != n.id.ID {
		if n.c.role == "superpeer" {
			if q, e := p.DecTTL(); e == nil {
				n.send(q)
			}
		}
		return
	}
	switch p.Type {
	case "HELLO":
		n.ensureNeighbor(p.Source)
		n.send(protocol.NewPacket("HELLO_ACK", n.id.ID, p.Source, map[string]any{"session_id": payloadString(p, "session_id")}))
	case "HELLO_ACK":
		n.debugf("received HELLO_ACK from %s; completing symmetric scan", p.Source[:8])
		n.completeSymmetricScan(p.Source, payloadString(p, "session_id"))
	case "PING":
		pong := protocol.NewPacket("PONG", n.id.ID, p.Source, map[string]any{"ping_id": p.ID})
		if compact {
			// Reply in the format the PING used so mixed-version fleets stay
			// interoperable during rolling upgrades.
			n.sendCompact(pong, address)
		} else {
			n.sendToAddress(pong, address)
		}
	case "PONG":
		n.handlePong(p)
	case "SYMMETRIC_BURST":
		n.ensureNeighbor(p.Source)
		n.handleSymmetricBurst(p, address)
	case "DATA":
		n.ensureNeighbor(p.Source)
		n.data(p)
	}
}

func (n *node) writeControlUDP(conn *net.UDPConn, data []byte, address *net.UDPAddr) (int, error) {
	written, err := conn.WriteToUDP(data, address)
	if err == nil {
		n.stats.controlTxPackets.Add(1)
		n.stats.controlTxBytes.Add(uint64(written + 28))
	}
	return written, err
}

func (n *node) handlePong(packet protocol.Packet) {
	id, ok := packet.Payload["ping_id"].(string)
	if !ok || packet.TTL != protocol.DefaultTTL {
		return
	}
	n.pingMu.Lock()
	probe, exists := n.pings[id]
	if exists && probe.peerID == packet.Source {
		delete(n.pings, id)
	}
	n.pingMu.Unlock()
	if !exists || probe.peerID != packet.Source || probe.sent.IsZero() {
		return
	}
	n.mu.Lock()
	if peer := n.neighbors[packet.Source]; peer != nil {
		peer.rttMS = float64(time.Since(probe.sent).Microseconds()) / 1000
	}
	n.mu.Unlock()
}

// A relay preserves the original source but decrements TTL. Such a packet
// proves that the routed path works, not that the UDP address it arrived from
// belongs to the source peer. Treating it as direct poisons peer.last with the
// relay address and makes a dead direct edge appear healthy again.
func confirmsDirectPath(packetType string, ttl int) bool {
	if ttl != protocol.DefaultTTL {
		return false
	}
	switch packetType {
	case "HELLO", "HELLO_ACK", "PING", "PONG":
		return true
	default:
		return false
	}
}

func (n *node) remember(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seen[id]; ok {
		return false
	}
	n.seen[id] = struct{}{}
	if len(n.seen) > 10000 {
		for k := range n.seen {
			delete(n.seen, k)
			break
		}
	}
	return true
}

// rememberFast keeps data-plane replay detection independent from the broad
// topology mutex. A fixed-size FIFO gives predictable O(1) work per packet and
// retains exactly the most recent fast packet IDs.
func (n *node) rememberFast(id [12]byte) bool {
	n.fastSeenMu.Lock()
	defer n.fastSeenMu.Unlock()
	if _, ok := n.fastSeen[id]; ok {
		return false
	}
	if len(n.fastSeenRing) < fastSeenCapacity {
		n.fastSeenRing = append(n.fastSeenRing, id)
	} else {
		delete(n.fastSeen, n.fastSeenRing[n.fastSeenNext])
		n.fastSeenRing[n.fastSeenNext] = id
		n.fastSeenNext++
		if n.fastSeenNext == fastSeenCapacity {
			n.fastSeenNext = 0
		}
	}
	n.fastSeen[id] = struct{}{}
	return true
}

func (n *node) nextPacketID(dst []byte) bool {
	if len(dst) != 12 {
		return false
	}
	for {
		previous := n.packetCounter.Load()
		if previous == ^uint64(0) {
			return false
		}
		count := previous + 1
		if n.packetCounter.CompareAndSwap(previous, count) {
			copy(dst, n.packetPrefix[:])
			binary.BigEndian.PutUint64(dst[len(n.packetPrefix):], count)
			return true
		}
	}
}

// meshHasOtherNodes reports whether the mesh currently knows at least one
// node other than this one. This is the only broadcast gate: requiring a
// same-NAT endpoint match before broadcasting used to disable LAN discovery
// exactly when it matters — at startup before the first STUN result, on
// multi-WAN routers where members of one physical LAN publish different
// external IPs, and whenever the published endpoint is stale.
func (n *node) meshHasOtherNodes() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for id := range n.neighbors {
		if id != n.id.ID {
			return true
		}
	}
	for id := range n.dir {
		if id != n.id.ID {
			return true
		}
	}
	return false
}

// copyUDPAddr returns a detached copy of a so stored endpoints never alias
// receive buffers.
func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

// virtualInterfaceName reports whether the interface is a well-known virtual
// bridge or adapter (Docker, libvirt, VMware, Hyper-V/WSL, VPN overlays).
// Addresses of such interfaces are unreachable for peers and would waste the
// LAN probe budget of the real addresses. Name heuristics cover Linux
// (docker0, veth*, virbr*, zt*, wg*, tun*, tap*), Windows (vEthernet (WSL),
// VirtualBox Host-Only, VMware Network Adapter) and OpenWrt, whose real LAN
// bridge br-lan must keep passing.
func virtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "lo" || strings.HasPrefix(lower, "lo0") || strings.Contains(lower, "loopback") || strings.Contains(lower, "bluetooth") {
		return true
	}
	// Docker user-defined bridges are br-<12 hex chars>; OpenWrt's real LAN
	// bridge is br-lan / br-wan and must not be filtered.
	if strings.HasPrefix(lower, "br-") && len(lower) > 6 {
		return true
	}
	for _, prefix := range []string{"docker", "veth", "virbr", "vmnet", "vboxnet", "wsl", "tailscale", "zerotier", "zt", "tun", "tap", "utun", "wg", "ifb", "dummy"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, part := range []string{"virtual", "vmware", "hyper-v"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// localSubnets returns the IPv4 prefixes of the up physical interfaces. The
// result is cached: enumerating interfaces on every keepalive would add
// syscalls to the control path. Loopback, link-local (169.254/16, adapters
// without DHCP on Windows), mesh-overlay and virtual-adapter addresses are
// excluded: they are unusable as LAN endpoint candidates and would otherwise
// crowd the real addresses out of the probe budget.
func (n *node) localSubnets() []netip.Prefix {
	n.subnetsMu.Lock()
	defer n.subnetsMu.Unlock()
	now := time.Now()
	if n.subnets != nil && now.Sub(n.subnetsAt) < localSubnetsRefresh {
		return n.subnets
	}
	subnets := make([]netip.Prefix, 0, 4)
	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || virtualInterfaceName(iface.Name) || (n.c.tun != "" && iface.Name == n.c.tun) {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipnet.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || n.isMeshAddr(ip) {
					continue
				}
				bits, _ := net.IPMask(ipnet.Mask).Size()
				subnets = append(subnets, netip.PrefixFrom(ip, bits))
			}
		}
	}
	n.subnets = subnets
	n.subnetsAt = now
	return subnets
}

// isMeshAddr reports whether ip belongs to the overlay (mesh) subnet of this
// node, so the TUN address never leaks into the LAN candidates: probing an
// overlay address over the physical network can never succeed.
func (n *node) isMeshAddr(ip netip.Addr) bool {
	mesh := n.meshIPv4.Load()
	if mesh == 0 || n.c.prefix <= 0 || n.c.prefix > 32 {
		return false
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], mesh)
	meshAddr, ok := netip.AddrFromSlice(raw[:])
	if !ok {
		return false
	}
	return netip.PrefixFrom(meshAddr, n.c.prefix).Contains(ip)
}

// advertisedLanAddrs lists this node's local UDP endpoint candidates
// ("ip:port") to publish through the coordinator: the IPv4 addresses of the
// up interfaces combined with the port of the main UDP socket. Peers unicast
// HELLO probes to them, which finds neighbors across cascaded routers where
// broadcast LAN discovery cannot reach.
func (n *node) advertisedLanAddrs() []string {
	port := n.currentUDPConn().LocalAddr().(*net.UDPAddr).Port
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	add := func(ip netip.Addr) {
		if len(out) >= lanAdvertiseMax || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	for _, prefix := range n.localSubnets() {
		add(prefix.Addr())
	}
	return out
}

// localSource reports whether a received datagram's source address means the
// traffic did not cross the internet: the address is private/link-local (NAT
// rewrites the source to a public address on any path that leaves the LAN)
// or belongs to a subnet of a local interface (exotic public ranges used as
// an unNATted LAN). CGNAT (100.64.0.0/10) and everything else is the
// internet: the packet came through the provider's network.
func (n *node) localSource(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
		return true
	}
	for _, subnet := range n.localSubnets() {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}

// sameNAT reports whether the peer's published external endpoint shares this
// node's external IP — a hint that both nodes sit behind one router, where a
// direct LAN path usually beats NAT hairpinning. It is never a guarantee of
// reachability: LAN segmentation, VLANs or AP isolation can still make the
// LAN address unusable. sameNAT therefore only trims a redundant duplicate
// HELLO while the LAN path is confirmed working, and it never withholds a
// recovery path.
func (n *node) sameNAT(p *peer) bool {
	if p == nil || p.Endpoint == "" || n.c.endpoint == "" {
		return false
	}
	peerIP := endpointIP(p.Endpoint)
	return peerIP != "" && peerIP == endpointIP(n.c.endpoint)
}

// freshLAN reports whether traffic was recently received from the peer's LAN
// address. Only a traffic-confirmed LAN path justifies skipping the public
// endpoint; a merely discovered candidate never does.
func freshLAN(p *peer, now time.Time) bool {
	return p != nil && p.lastLAN != nil && now.Sub(p.lastLANRX) < lanHoldTimeout
}

func (n *node) touch(id string, a net.Addr) {
	// Classify the source before taking the topology lock: the subnet cache
	// may refresh and touch the network stack.
	lanSource := false
	address, isUDP := a.(*net.UDPAddr)
	if isUDP {
		lanSource = n.localSource(address.IP)
	}
	now := time.Now()
	n.mu.Lock()
	if p := n.neighbors[id]; p != nil {
		if isUDP {
			if lanSource {
				// A LAN address always wins for sending: same-segment traffic
				// does not traverse the NAT device at all.
				p.lastLAN = copyUDPAddr(address)
				p.lastLANRX = now
				p.last = p.lastLAN
			} else if !freshLAN(p, now) || p.last != net.Addr(p.lastLAN) {
				// Public source: either a real WAN path or NAT hairpin. The
				// send target keeps a small hysteresis (below) so one hairpin
				// datagram does not flip where the next probes are sent.
				p.last = copyUDPAddr(address)
			}
		} else {
			p.last = a
		}
		// Classification is strictly per-packet: the source of the most
		// recent datagram decides LAN vs internet, with no holdover. NAT
		// rewrites the source to a public address on any path that leaves
		// the LAN, so a private source means the traffic stayed local.
		p.lastPathLAN = lanSource
		p.lastRX = now
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
	// Unknown packets can arrive in bursts (or be sent by a stale/malicious
	// member). Coalesce them into one asynchronous refresh so the UDP receive
	// loop is never blocked and they cannot create a control-plane CPU storm.
	if !n.topologyRefreshMu.TryLock() {
		return
	}
	now := time.Now()
	if now.Before(n.topologyRefreshNext) {
		n.topologyRefreshMu.Unlock()
		return
	}
	n.topologyRefreshNext = now.Add(refresh)
	go func() {
		defer n.topologyRefreshMu.Unlock()
		n.logf("received traffic from new node %s; refreshing topology", id[:8])
		if err := n.bootstrap(); err != nil {
			n.logf("topology refresh failed: %v", err)
		}
	}()
}

func (n *node) linkHealth(ctx context.Context) {
	ticker := time.NewTicker(linkHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deadEdges := make([]peer, 0)
			stateChanged := false
			n.mu.Lock()
			for id, peer := range n.neighbors {
				live := n.usable(peer)
				if peer.up != live {
					stateChanged = true
					peer.up = live
					state := "down"
					if live {
						state = "up"
					}
					n.logf("link %s %s", id[:8], state)
				}
				if !live {
					deadEdges = append(deadEdges, *peer)
				}
			}
			n.mu.Unlock()
			if stateChanged {
				n.mu.Lock()
				n.routes = n.buildRoutes()
				n.mu.Unlock()
			}
			for _, peer := range deadEdges {
				if n.c.nat == "symmetric" && peer.Role == "superpeer" {
					n.logf("symmetric edge %s is down; retrying scan", peer.ID[:8])
				} else {
					n.logf("edge %s is down; retrying HELLO", peer.ID[:8])
				}
				n.retryDeadEdge(peer.ID, peer)
			}
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

// fastAAD binds the immutable packet ID as well as the source and destination
// to the existing end-to-end tag, without a second per-packet MAC.
func fastAAD(dst, peerAAD, packetID []byte) []byte {
	dst = append(dst, peerAAD...)
	return append(dst, packetID...)
}

// fast handles compact encrypted frames. Destinations authenticate the packet ID
// before duplicate suppression; relays cannot verify the end-to-end tag and
// forward by changing the unauthenticated TTL. Frame layout: MIP1 | TTL | source |
// destination | packet ID | nonce | ciphertext | AEAD tag.
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
// tunLoop reads IP packets from the host and injects received packets back.
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

// Broadcast is not an overlay unicast destination. Hosts commonly emit it
// for discovery, and routing it through the mesh would only create repeated
// failed lookups and debug-log floods.
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
// sendIP encrypts a TUN packet and forwards it toward its mesh destination.
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

// translateLocalPacket performs a stateless 1:1 prefix translation. Host bits
// are preserved, so identical physical LANs remain distinct inside the mesh.
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
// stunEndpoint queries available STUN servers to discover the public UDP mapping.
func stunEndpoint(c *net.UDPConn, onPacket func([]byte, *net.UDPAddr), bootstrap ...string) (string, string, error) {
	// STUN shares the node's UDP socket with the receive loop. Always restore
	// the socket deadline so a probe cannot leave the data plane with a stale
	// two-second read timeout.
	defer c.SetReadDeadline(time.Time{})
	servers := []string{
		"stun.nextcloud.com:3478",
		"stun.miwifi.com:3478",
		"stun.sipgate.net:3478",
		"stun.zadarma.com:3478",
		"stun.ipfire.org:3478",
	}
	type resolvedServer struct {
		address *net.UDPAddr
		err     error
	}
	resolved := make(chan resolvedServer, len(servers))
	for _, server := range servers {
		go func(server string) {
			address, err := resolveMeshUDPAddr(server, bootstrap...)
			resolved <- resolvedServer{address: address, err: err}
		}(server)
	}
	pending := make(map[[12]byte]struct{}, len(servers))
	resolveFailures := 0
	writeFailures := 0
	for range servers {
		result := <-resolved
		if result.err != nil {
			resolveFailures++
			continue
		}
		var transaction [12]byte
		if _, err := rand.Read(transaction[:]); err != nil {
			continue
		}
		request := make([]byte, 20)
		binary.BigEndian.PutUint16(request, 1)
		binary.BigEndian.PutUint32(request[4:], 0x2112A442)
		copy(request[8:], transaction[:])
		if _, err := c.WriteToUDP(request, result.address); err == nil {
			pending[transaction] = struct{}{}
		} else {
			writeFailures++
		}
	}
	if len(pending) == 0 {
		return "", "", fmt.Errorf("no STUN server could be contacted (resolved=%d/%d, write failures=%d)", len(servers)-resolveFailures, len(servers), writeFailures)
	}

	// Send all probes before waiting. The previous sequential implementation
	// could spend three seconds on every unavailable server, delaying startup
	// and network recovery by up to nine seconds.
	_ = c.SetReadDeadline(time.Now().Add(stunProbeTimeout))
	mapped := make([]string, 0, 2)
	buffer := make([]byte, 2048)
	for len(pending) > 0 && len(mapped) < 2 {
		length, address, err := c.ReadFromUDP(buffer)
		if err != nil {
			break
		}
		if length < 20 {
			if onPacket != nil {
				onPacket(append([]byte(nil), buffer[:length]...), address)
			}
			continue
		}
		var transaction [12]byte
		copy(transaction[:], buffer[8:20])
		if _, ok := pending[transaction]; !ok {
			if onPacket != nil {
				onPacket(append([]byte(nil), buffer[:length]...), address)
			}
			continue
		}
		if endpoint, ok := stunMappedEndpoint(buffer[:length], transaction); ok {
			delete(pending, transaction)
			mapped = append(mapped, endpoint)
		}
	}
	if len(mapped) == 0 {
		return "", "", errors.New("no STUN server responded")
	}
	if len(mapped) == 1 || mapped[0] == mapped[1] {
		return mapped[0], "cone", nil
	}
	return mapped[0], "symmetric", nil
}

func stunMappedEndpoint(response []byte, transaction [12]byte) (string, bool) {
	if len(response) < 20 || binary.BigEndian.Uint16(response) != 0x0101 ||
		binary.BigEndian.Uint32(response[4:8]) != 0x2112A442 || !bytes.Equal(response[8:20], transaction[:]) {
		return "", false
	}
	for offset := 20; offset+4 <= len(response); {
		typ, size := binary.BigEndian.Uint16(response[offset:]), int(binary.BigEndian.Uint16(response[offset+2:]))
		end := offset + 4 + size
		if end > len(response) {
			return "", false
		}
		value := response[offset+4 : end]
		if typ == 0x0020 && len(value) >= 8 && value[1] == 1 {
			port := binary.BigEndian.Uint16(value[2:4]) ^ 0x2112
			ip := binary.BigEndian.Uint32(value[4:8]) ^ 0x2112A442
			return fmt.Sprintf("%d.%d.%d.%d:%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port), true
		}
		offset += 4 + (size+3)&^3
	}
	return "", false
}

func resolveMeshUDPAddr(address string, bootstrap ...string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.ResolveUDPAddr("udp4", address)
	}
	// Prefer the platform resolver with an explicit udp4 network. This avoids
	// IPv6 answers and is more reliable on minimal Linux/container images where
	// the custom resolver has no usable nameserver configuration.
	if len(bootstrap) == 0 {
		if resolved, resolveErr := net.ResolveUDPAddr("udp4", address); resolveErr == nil && resolved.IP.To4() != nil {
			return resolved, nil
		}
	}
	if resolved, resolveErr := resolveUDPAddrWithResolver(address, meshResolver(bootstrap...)); resolveErr == nil {
		return resolved, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := meshResolver().LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, raw := range ips {
		if ip := net.ParseIP(raw).To4(); ip != nil {
			p, err := net.LookupPort("udp", port)
			if err != nil {
				return nil, err
			}
			return &net.UDPAddr{IP: ip, Port: p}, nil
		}
	}
	return nil, errors.New("DNS returned no IPv4 address")
}

func resolveUDPAddrWithResolver(address string, resolver *net.Resolver) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	for _, raw := range ips {
		if ip := net.ParseIP(raw).To4(); ip != nil {
			return &net.UDPAddr{IP: ip, Port: p}, nil
		}
	}
	return nil, errors.New("DNS returned no IPv4 address")
}
