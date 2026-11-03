// Command mesh-node runs an encrypted UDP overlay endpoint and optional service gateway.
package main

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"io"
	"log"
	"net"
	_ "net/http/pprof"
	"net/netip"
	"os"
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
	pingInterval  = 15 * time.Second
	helloInterval = 90 * time.Second
	// compactHelloCapabilityTTL bounds how long a peer's demonstrated compact
	// support is trusted for HELLO/HELLO_ACK. Live paths refresh it every ping
	// interval; seven days covers week-long sleeps without relearning churn.
	compactHelloCapabilityTTL = 7 * 24 * time.Hour
	linkHealthInterval        = 5 * time.Second
	refresh                   = 5 * time.Second
	heartbeat                 = 20 * time.Second
	telemetryInterval         = 15 * time.Second
	recoveryCheck             = 5 * time.Second
	topologyPoll              = 90 * time.Second
	linkTimeout               = 30 * time.Second
	// Upper bound for one blocking UDP receive. The receive loop renews the
	// deadline each iteration; the brief unlock between reads lets rebind or
	// STUN take the exclusive udpReadMu lock (see receiveSocket).
	udpReadWindow = 1 * time.Second
	linkGrace     = 20 * time.Second
	// Probe-derived link quality smoothing. RTT is an EWMA so one delayed
	// probe cannot swing route costs; loss moves 10% per probe round toward
	// the observed outcome, so a link must miss several rounds before it is
	// reported to the coordinator as lossy.
	rttProbeSmooth   = 0.7 // weight of the previous RTT sample in the EWMA
	lossProbeRecover = 0.9 // loss decay on every answered probe
	lossProbePenalty = 0.1 // loss increment per expired probe round
	// Bounded retries for the post-reconnect endpoint check: right after a
	// radio transition (LTE <-> Wi-Fi, doze resume) DNS and STUN often need a
	// few seconds to become usable, and a single failed check used to leave
	// the node advertising a stale endpoint until the next disconnect.
	endpointRefreshRetries    = 4
	endpointRefreshRetryDelay = 5 * time.Second
	// Slow-clock re-verification of the public UDP endpoint on the CURRENT
	// socket. Peers keepalive an old NAT mapping with inbound probes, so a
	// STUN check right after reconnect can still return the old address; the
	// mapping then dies the moment peers go quiet while the coordinator keeps
	// advertising it. A periodic check bounds that staleness even when no
	// reconnect fires at all.
	endpointVerifyInterval = 15 * time.Minute
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
	// Exponential backoff cap between burst rounds toward one relay. On
	// carrier NATs (LTE CGNAT) a burst allocates hundreds of UDP mappings;
	// repeating it every few seconds only floods conntrack and drains the
	// battery without improving the odds.
	symmetricBurstBackoffMax = 90 * time.Second
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
	server, token, inviteToken, role, nat, bind, bindIface, endpoint, meshIP, tun, state, call, requestFile, pprofListen, controlCA string
	port, capacity, prefix, symmetricScanStep                                                                                       int
	noRelay, autoTUN, debug, resetConfig, controlInsecure                                                                           bool
	fastWorkers, deliverWorkers                                                                                                     int
	statsInterval                                                                                                                   time.Duration
	services, allows, bootstrapDNS                                                                                                  multi
}
type multi []string

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
	// compactHelloUntil caches how long this peer has demonstrated binary-format
	// support, so HELLO/HELLO_ACK can ride the ~70-byte compact encoding. It is
	// refreshed by every compact PING/PONG/HELLO/HELLO_ACK received from the
	// peer and expires for silent neighbors so a downgraded or stale entry
	// falls back to the JSON envelope for one round.
	compactHelloUntil time.Time
	LANAddrs          []string `json:"lan_addrs,omitempty"` // coordinator-advertised local addresses
	discovered        time.Time
	up                bool
	rttMS             float64
	// lossEMA is the smoothed keepalive probe loss in [0,1]. It feeds the
	// telemetry Loss report and survives topology refreshes like rttMS.
	lossEMA float64
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

// permits reports whether an inbound IPv4 packet from the mesh may enter the
// local stack. ICMP always passes (ping and path diagnostics stay usable);
// TCP/UDP must target a listed destination port; other protocols are dropped.
// Non-first fragments are dropped because the port lives in the first
// fragment — reassembly cannot complete without it anyway.

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
// hexCache caches pre-computed hex-encoded node IDs to avoid calling
// hex.EncodeToString on every packet in the receive hot path.
// Profiling showed this was allocating ~4 strings/packet at 520-byte throughput.
type hexCache struct {
	selfHex string // full 32-char hex of self.id.ID, used when encoding dest
	peerHex string // full 32-char hex of peer id, used for map lookups in fast path
}
type cachedKey struct {
	public   string
	key      []byte
	aead     cipher.AEAD
	nonces   *protocol.NonceSequence
	peerID   [16]byte
	openAAD  []byte
	sealAAD  []byte
	hexCache hexCache // pre-computed for fast path
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

// symmetricBurstCall lets concurrent callers share one in-flight port scan.
// Callers that arrive while a burst is already running toward a relay join it
// and return the same outcome instead of opening another 500 sockets.
type symmetricBurstCall struct {
	done chan struct{}
	ok   bool
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
	lanSubnetCache     []netip.Prefix // RFC1918 subnets on non-modem interfaces
	lanSubnetsAt       time.Time
	udpReadMu          sync.RWMutex
	recoveryMu         sync.Mutex
	recoveryNext       time.Time
	recoveryFails      int
	control            *websocket.Conn
	controlConnected   bool
	controlMu          sync.Mutex
	controlRxAt        atomic.Int64
	roamRefreshAt      atomic.Int64
	networkGen         atomic.Uint64 // bumped on every UDP rebind; stale bursts detect roaming
	closing            atomic.Bool
	controlCall        sync.Mutex
	controlReply       chan controlFrame
	pingMu             sync.Mutex
	pings              map[string]pingProbe
	linksRejected      atomic.Bool // coordinator cannot accept piggybacked link reports
	goarchRejected     atomic.Bool // coordinator cannot accept the goarch report
	lanAddrsRejected   atomic.Bool // coordinator cannot accept the lan_addrs report
	revokedLogged      atomic.Bool // re-enrollment blocked: identity banned by coordinator
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
	altRoutes          map[string]string
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
	// symmetricBurstMu guards symmetricBurstInFlight: startup, roaming
	// recovery and per-edge retries all used to start their own 500-socket
	// scan for the same superpeer; concurrent rendezvous requests also
	// cancelled each other on the relay side, so neither scan could succeed.
	symmetricBurstMu       sync.Mutex
	symmetricBurstInFlight map[string]*symmetricBurstCall
	symmetricFailures      map[string]int       // consecutive failed bursts per relay
	symmetricBackoff       map[string]time.Time // next allowed burst attempt per relay
	edgeRetryMu            sync.Mutex
	edgeRetries            map[string]bool
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

const (
	unifiedStateFile      = "mesh-node.json"
	interactiveConfigFile = "mesh-node-config.json"
)

type savedConfig struct {
	Server, Token, InviteToken, Role, NAT, Bind, BindIface, Endpoint, MeshIP, TUN, State, ControlCA string
	Port, Capacity, Prefix, SymmetricScanStep                                                       int
	NoRelay, AutoTUN, Debug, ControlInsecure                                                        bool
	PrivateKey                                                                                      string `json:"private_key,omitempty"`
}


// loadIdentity loads the persistent node key, creating one on first use.


// newNode initializes runtime state and network resources from configuration.

// UDP has no backpressure. Larger kernel queues absorb short bursts while the
// workers are decrypting or routing an earlier batch. These calls are
// best-effort because operating systems may clamp the requested size.

type controlFrame struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Status int             `json:"status,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
}

// connectControl opens the persistent WebSocket used for coordinator events.

// meshResolver avoids Android configurations that point libc DNS at an
// unavailable IPv6 loopback resolver (::1). It deliberately resolves only
// IPv4 addresses because the mesh transport is IPv4/UDP based.



// pokeControlReconnect rebuilds the control channel as soon as the reader
// observes a dead connection. Without it a node stayed offline for up to a
// heartbeat interval even though it had already lost the coordinator. The
// jitter prevents every node from dialing in the same millisecond after a
// coordinator restart.

// androidRuntimeFn is a hook so tests can simulate Android detection.
var androidRuntimeFn = androidRuntime


// request sends compact JSON frames over one long-lived WebSocket. A failed
// connection is recreated once, which also handles NAT or server restarts.

// refreshEndpointAfterControlReconnect is intentionally asynchronous. A
// restored WebSocket must not wait for STUN or topology rebuilding. A fresh
// UDP socket is used because Android may keep the old socket on Wi-Fi after a
// switch to LTE.

// refreshEndpointAttempt re-checks the public UDP endpoint after a control
// reconnect. Failures are retried with a fixed delay up to
// endpointRefreshRetries times; recoveryMu.TryLock keeps overlapping
// attempts (late retries vs. a newer reconnect) mutually exclusive.

// verifyEndpoint periodically re-checks the public UDP mapping on the
// CURRENT socket (no rebind: the socket is alive, and network switches are
// handled by monitorNetwork/roamRefresh). It bounds how long the node can
// keep advertising a stale NAT mapping even when no control reconnect fires
// at all: peers keep an old mapping alive with inbound probes, so the
// post-reconnect STUN check can return the previous address and the mapping
// only dies later, when peers go quiet, while the coordinator keeps
// pointing every newcomer at it.

// applyEndpointChange adopts a freshly observed public endpoint. A port-only
// change is a normal NAT rebinding and just re-teaches peers through the
// current transport; an IP change rebuilds it and re-registers immediately
// so the coordinator stops advertising the dead mapping.



// register announces this node and refreshes its coordinator lease.

// bootstrap fetches the current peer list and forwarding topology.

// applyTopology updates peer state and routes from a coordinator snapshot.



// A cone relay must only scan after it has received a SYMMETRIC_BURST. Starting
// from a topology push races ahead of the symmetric peer, while retaining a
// scan after an edge disappears wastes tens of seconds probing an obsolete
// mapping.

type qitem struct {
	id   string
	cost float64
}
type pq []qitem


// computeRoutes runs Dijkstra from this node over the current link set and
// returns two next-hop tables: the primary cheapest-path hops, and fallback
// hops that leave through a different neighbor than the primary route. The
// fallback table lets traffic keep flowing while the primary edge is down or
// being re-measured instead of dropping packets until the next topology
// event or recompute window.
//
// Caller must hold at least n.mu.RLock.

// firstHopTable is Dijkstra from this node; exclude (when non-empty) is a
// neighbor that must not be used as the first hop. Unusable direct neighbors
// are skipped on the first step so a route never starts from an edge that
// has not carried traffic recently. Returns the predecessor map.

// firstHopFrom walks the predecessor chain back to the node right after self.

// start brings up transports, discovery, packet workers, and health loops.

// establishSymmetricTransport establishes one UDP mapping per superpeer. A
// symmetric NAT allocates a mapping per destination, so a single selected
// socket cannot serve all superpeers.
// establishSymmetricTransport opens per-relay UDP mappings for symmetric NAT.

// relayLANLive reports whether the relay currently has a traffic-confirmed
// LAN path, which makes a symmetric probe burst unnecessary: LAN traffic
// flows through the regular socket without traversing the NAT device.

// someRelayLANLive reports whether at least one superpeer has a live LAN path.



// symmetricBackoffWait reports how long a burst toward relayID must wait
// before the next attempt. Zero means "go ahead".

// symmetricBurstFailed records a failed burst and schedules the next attempt
// with exponential backoff (2s, 4s, 8s, ... capped).

// symmetricBurstSucceeded clears the per-relay failure history.



// symmetricRelay is kept as a deterministic compatibility helper for callers
// that only need the preferred relay. Establishment itself uses all relays.



// installSymmetricConn keeps the first successful socket as the node's
// primary socket and retains every later socket for its own superpeer.




// defaultRouteInterfaceFn is a hook so tests can simulate route lookup.
var defaultRouteInterfaceFn = defaultRouteInterface

// resolveBindIface resolves the configured interface name for UDP sockets.
// "auto" selects the current default-route interface and is re-evaluated on
// every rebind, so Wi-Fi <-> LTE switches move the binding along. Empty means
// "auto" on Android and wildcard elsewhere: wildcard UDP on Android is pulled
// into VPN TUNs (VLESS/Happ, WireGuard apps) by policy routing, which
// silently breaks hole punching. "none" forces the wildcard socket.

// rebindUDPConn drops the socket created on the previous network and creates
// a new one. On Android a wildcard-bound UDP socket can remain associated with
// the Wi-Fi Network after the default network changes to LTE; refreshing STUN
// on that socket then keeps returning the dead mapping.




// scanSymmetricNeighbor probes likely external ports until the peer responds.

// symmetricScanPorts scans ports in sparse, offset passes.  A 200-port step
// for a peer advertised on 54532 starts at 54332, continues with 54732 through
// 65532, wraps to 132, and only then begins the next pass around 54531.
//
// The advertised port is included at the end of its own pass, before the scan
// shifts the pass center down by one.








// encodePacketForPeer picks the wire format for one outbound UDP packet.
// HELLO and HELLO_ACK ride the ~70-byte compact encoding when the destination
// has demonstrated compact support and carries no session_id (symmetric-scan
// probes echo a session_id in HELLO_ACK and stay JSON). Packets with a
// decremented TTL are being relayed: DecodeCompact restores TTL to DefaultTTL,
// so a relayed compact frame would let the receiver mistake the relay address
// for a direct path — those stay JSON, matching the relay re-encoding rule.
// Everything else keeps the JSON envelope, so pre-compact peers are unaffected.

// markCompactHello records that the peer emitted a compact-format packet.

// speaksCompactHello reports whether the peer recently proved binary-format
// support. Peers that never do (pre-compact versions) permanently keep the
// JSON HELLO envelope they have always received.

// sendCompact emits PING/PONG in the binary keepalive format, cutting each
// keepalive from ~225 to ~70 bytes. It mirrors sendToAddress and falls back
// to the JSON envelope when the packet cannot be compact-encoded.

// startLANDiscovery gives peers on the same broadcast domain a private
// endpoint candidate. Public STUN endpoints are not guaranteed to support
// NAT hairpinning, so two machines on one LAN must not be forced through the
// public address of their router.
// startLANDiscovery listens for nearby peers that can use a direct LAN path.

// lanDiscoveryBurst repeats the broadcast a few times with an exponential
// backoff right after startup. A peer that is still bootstrapping cannot use
// discovery candidates that arrive before its topology is ready; short
// retries close that window instead of waiting a full interval.

// probeLanCandidates unicasts HELLO probes to the LAN addresses peers
// advertised through the coordinator. Broadcast discovery cannot cross a
// router, so this is the only way to find neighbors in an adjacent subnet of
// the same physical network (cascaded routers). The per-peer interval and
// fresh-LAN checks keep the cost at a few small datagrams per tick; the
// candidate set is re-checked on a fixed schedule instead of waiting for a
// topology push, so candidates also work in a fully stable network.


// subnetBroadcastAddrs returns the directed broadcast address of every
// physical local subnet. Unlike 255.255.255.255, a directed broadcast
// follows the routing table and leaves through the interface that owns the
// subnet, which makes LAN discovery work on routers and multi-NIC hosts.

// broadcastForPrefix returns the directed broadcast address of a prefix:
// the masked network address with all host bits set. /31 and /32 have no
// broadcast address and /0 is the default route, so they report false.



// restoreTUNNetwork repairs host-side state that a mobile network switch can
// discard. The installed-route cache is cleared because routes may be gone in
// the kernel even though they are still present in the cache.


// resetSymmetricRelay drops only one superpeer mapping. It is used when a
// single edge dies, so the remaining symmetric links stay usable while this
// relay gets a fresh rendezvous and port scan.

const (
	edgeRetryAttempts = 3
	edgeRetryDelay    = 2 * time.Second
)

// retryDeadEdge keeps retrying an individual failed edge. Global network
// recovery is intentionally conservative and only runs when every neighbor is
// stale, so it cannot be the mechanism that revives one dead edge in an
// otherwise healthy mesh.
// symmetricEdgeNeedsRescan reports whether a dead symmetric superpeer edge
// must get a new probe burst. A merely installed transport socket does not
// count as alive: it can linger after the relay stopped answering, which
// used to block retries forever and left the edge permanently down.




// recoverNetwork rebuilds local connectivity after all neighbor paths go stale.

// networkFingerprint summarizes the currently up IPv4 interface configuration.
// It deliberately excludes the mesh TUN: configuring the TUN during recovery
// must not look like a roaming event and trigger another recovery.

// fingerprintInterfaces joins per-interface address lists into one string.
// Sorting makes the result independent of enumeration order, loopback and
// interfaces without an IPv4 address are skipped, so plain carrier-grade NAT
// rebinds that keep the interface set stable do not spam recovery.

// monitorNetwork polls the interface table and reacts to Wi-Fi <-> LTE style
// switches within a few seconds. Waiting for traffic failures instead leaves a
// mobile node blind for 30-90 s: half-open control connections and UDP sockets
// pinned to the previous network keep looking alive far too long.

// handleNetworkChange starts a roaming refresh: a new network invalidates the
// UDP socket, all cached peer paths and often the control connection.

// roamRefresh rebuilds the whole transport after a network switch. Unlike the
// post-reconnect endpoint check it never trusts "the external endpoint looks
// the same": on Android the old socket can stay pinned to the dead Wi-Fi
// network while STUN still answers through it. The socket is always rebound
// and every cached peer path is dropped.

// monitorControl force-closes a control WebSocket that stopped receiving.
// A network switch usually leaves the old TCP connection half-open instead of
// sending a RST: writes appear to succeed, no reply ever arrives, and without
// this watchdog the node waits for a request timeout before even trying to
// reconnect. Topology pushes and symmetric-scan events are lost meanwhile.



type pingTarget struct {
	id       string
	endpoint string
	observed *net.UDPAddr
	lan      *net.UDPAddr // unconfirmed LAN candidate to re-probe
}

// sendDirect bypasses mesh routing. Keepalive RTT is a measurement of a
// physical neighbor link, not of a potentially changing multi-hop route.

// PONG removes its matching entry, but offline peers never answer. Bound the
// bookkeeping for those peers so a long-running node does not accumulate one
// ping timestamp per keepalive interval forever.

// noteLostProbes folds expired probe rounds into the smoothed loss estimate
// that is reported to the coordinator as LinkMeasurement.Loss.

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

// reportTelemetry sends link measurements only when they changed (link set,
// up/down state, or a meaningful RTT shift) or when the keepalive window
// elapsed. In a stable network this removes nearly all telemetry traffic;
// any change is still reported within one telemetryInterval, so monitoring
// responsiveness is unchanged. Fresh RTT for every link also arrives with
// each register heartbeat.
// reportTelemetry sends current link health to the coordinator when needed.

// telemetryChanged reports whether the new measurements differ from the last
// sent snapshot enough to justify a report. RTT jitter within 30% and 3 ms is
// deliberately not reported: the coordinator smooths RTT with an EMA and a
// fresh exact value arrives with every register heartbeat anyway.

// lossDrifted reports a meaningful loss shift. The estimate moves 0.1 per
// probe round, so a 0.1 step means roughly one lost keepalive round and is
// worth telling the coordinator; sub-step jitter stays silent.


// nextHop selects a cached or newly computed route for a destination.

// fallbackHop returns the precomputed alternate next hop for a destination:
// the shortest path that leaves through a different neighbor than the primary
// route. Traffic keeps flowing while the primary edge is down or being
// re-measured instead of dropping until a recompute window opens.






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



// receive starts readers for every active UDP socket.




// handleDatagram authenticates and dispatches one received UDP packet.



// A relay preserves the original source but decrements TTL. Such a packet
// proves that the routed path works, not that the UDP address it arrived from
// belongs to the source peer. Treating it as direct poisons peer.last with the
// relay address and makes a dead direct edge appear healthy again.


// rememberFast keeps data-plane replay detection independent from the broad
// topology mutex. A fixed-size FIFO gives predictable O(1) work per packet and
// retains exactly the most recent fast packet IDs.


// meshHasOtherNodes reports whether the mesh currently knows at least one
// node other than this one. This is the only broadcast gate: requiring a
// same-NAT endpoint match before broadcasting used to disable LAN discovery
// exactly when it matters — at startup before the first STUN result, on
// multi-WAN routers where members of one physical LAN publish different
// external IPs, and whenever the published endpoint is stale.

// copyUDPAddr returns a detached copy of a so stored endpoints never alias
// receive buffers.

// virtualInterfaceName reports whether the interface is a well-known virtual
// bridge or adapter (Docker, libvirt, VMware, Hyper-V/WSL, VPN overlays).
// Addresses of such interfaces are unreachable for peers and would waste the
// LAN probe budget of the real addresses. Name heuristics cover Linux
// (docker0, veth*, virbr*, zt*, wg*, tun*, tap*), Windows (vEthernet (WSL),
// VirtualBox Host-Only, VMware Network Adapter) and OpenWrt, whose real LAN
// bridge br-lan must keep passing.

// localSubnets returns the IPv4 prefixes of the up physical interfaces. The
// result is cached: enumerating interfaces on every keepalive would add
// syscalls to the control path. Loopback, link-local (169.254/16, adapters
// without DHCP on Windows), mesh-overlay and virtual-adapter addresses are
// excluded: they are unusable as LAN endpoint candidates and would otherwise
// crowd the real addresses out of the probe budget.

// lanSubnets returns only the subnets that can plausibly host LAN peers:
// RFC1918 addresses on non-modem interfaces. Carrier ranges on rmnet/ccmni
// belong to the provider's internal network and must never be advertised or
// probed as LAN candidates.

// hasLAN reports whether any interface currently offers a private LAN subnet.
// A phone on mobile data has none, which disables LAN probing entirely:
// without this gate the node kept unicasting HELLOs to 192.168.x addresses
// through the carrier network after leaving Wi-Fi.

// collectSubnets enumerates IPv4 prefixes of up physical interfaces. With
// lanOnly, modem interfaces are skipped and only RFC1918 ranges are kept.

// isMeshAddr reports whether ip belongs to the overlay (mesh) subnet of this
// node, so the TUN address never leaks into the LAN candidates: probing an
// overlay address over the physical network can never succeed.

// advertisedLanAddrs lists this node's local UDP endpoint candidates
// ("ip:port") to publish through the coordinator: the IPv4 addresses of the
// up interfaces combined with the port of the main UDP socket. Peers unicast
// HELLO probes to them, which finds neighbors across cascaded routers where
// broadcast LAN discovery cannot reach.

// localSource reports whether a received datagram's source address means the
// traffic did not cross the internet: the address is private/link-local (NAT
// rewrites the source to a public address on any path that leaves the LAN)
// or belongs to a subnet of a local interface (exotic public ranges used as
// an unNATted LAN). CGNAT (100.64.0.0/10) and everything else is the
// internet: the packet came through the provider's network.

// wwanInterfaceName reports whether the interface belongs to a mobile-data
// modem (Android rmnet*/ccmni*, iOS pdp*, generic wwan*). Addresses of such
// interfaces live inside the carrier's internal network: probing or
// advertising them as LAN candidates sends packets into the provider's
// network and never reaches a peer.

// lanCandidateUsable reports whether a coordinator-advertised LAN address
// can plausibly be on-link for this node right now: it must be private
// (RFC1918) while the node itself has a LAN, or sit inside one of this
// node's own subnets (exotic public LAN ranges). Private candidates on a
// mobile-data-only node fail the first check: without a local LAN there is
// no way a 192.168.x address is reachable, and probing would leak packets
// into the carrier's network.

// sameNAT reports whether the peer's published external endpoint shares this
// node's external IP — a hint that both nodes sit behind one router, where a
// direct LAN path usually beats NAT hairpinning. It is never a guarantee of
// reachability: LAN segmentation, VLANs or AP isolation can still make the
// LAN address unusable. sameNAT therefore only trims a redundant duplicate
// HELLO while the LAN path is confirmed working, and it never withholds a
// recovery path.

// freshLAN reports whether traffic was recently received from the peer's LAN
// address. Only a traffic-confirmed LAN path justifies skipping the public
// endpoint; a merely discovered candidate never does.






// handleLegacyIPFragment accepts the JSON-sealed fragment representation used
// before the compact MIP1 data plane.  Keeping it makes rolling upgrades safe:
// a Go destination can receive packets from an older mesh node.



// fastAAD binds the immutable packet ID as well as the source and destination
// to the existing end-to-end tag, without a second per-packet MAC.

// fast handles compact encrypted frames. Destinations authenticate the packet ID
// before duplicate suppression; relays cannot verify the end-to-end tag and
// forward by changing the unauthenticated TTL. Frame layout: MIP1 | TTL | source |
// destination | packet ID | nonce | ciphertext | AEAD tag.


// tunLoop reads IP packets from the host and injects received packets back.


// Broadcast is not an overlay unicast destination. Hosts commonly emit it
// for discovery, and routing it through the mesh would only create repeated
// failed lookups and debug-log floods.

// sendIP encrypts a TUN packet and forwards it toward its mesh destination.






// translateLocalPacket performs a stateless 1:1 prefix translation. Host bits
// are preserved, so identical physical LANs remain distinct inside the mesh.



// stunEndpoint queries available STUN servers to discover the public UDP mapping.



