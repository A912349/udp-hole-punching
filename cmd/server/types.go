package main

import (
	"database/sql"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
)

type node struct {
	ID            string               `json:"node_id"`
	PublicKey     string               `json:"public_key"`
	NAT           string               `json:"nat_type"`
	Role          string               `json:"role"`
	Endpoint      string               `json:"endpoint"`
	Capacity      int                  `json:"capacity"`
	MeshIP        string               `json:"mesh_ip"`
	GoArch        string               `json:"goarch,omitempty"`
	RequestedRole string               `json:"requested_role"`
	Relay         bool                 `json:"relay_capable"`
	LastSeen      int64                `json:"last_seen"`
	CreatedAt     int64                `json:"created_at"`
	ConnectedAt   int64                `json:"connected_at"`
	UptimeSeconds int64                `json:"uptime_seconds,omitempty"`
	Online        bool                 `json:"online"`
	Name          string               `json:"name,omitempty"`
	Routes        []routeAdvertisement `json:"routes,omitempty"`
	DNSRecords    []dnsRecord          `json:"dns_records,omitempty"`
	// LANAddrs are the node's local UDP addresses ("ip:port") as seen on its
	// own interfaces. Peers unicast HELLO probes to them: broadcast discovery
	// cannot cross routers, but unicast reaches adjacent subnets of the same
	// physical network (cascaded routers) and lets touch() confirm a real
	// LAN path.
	LANAddrs []string `json:"lan_addrs,omitempty"`
}
type routeAdvertisement struct {
	LAN     string `json:"lan_cidr"`
	Virtual string `json:"virtual_cidr"`
}
type dnsRecord struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	VirtualIP string `json:"virtual_ip,omitempty"`
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

// firewallConfig is the coordinator-managed mesh firewall of one node. It
// governs inbound connections to the node's mesh IP: "allow_all" (the
// default) accepts everything, "whitelist" accepts only the listed
// destination ports. ICMP always passes.
type firewallConfig struct {
	Mode  string   `json:"mode"`
	Ports []string `json:"ports"`
}
type link struct {
	A      string  `json:"a"`
	B      string  `json:"b"`
	Cost   float64 `json:"cost"`
	RTTMS  float64 `json:"rtt_ms,omitempty"`
	Loss   float64 `json:"loss,omitempty"`
	Status string  `json:"status,omitempty"`
	// ViaLAN is true when node telemetry observed traffic on a LAN path for
	// this edge. It is a measurement, so an edge between same-subnet peers
	// that actually flows over the internet stays false.
	ViaLAN bool `json:"via_lan,omitempty"`
}
type server struct {
	db                                          *sql.DB
	registerLookupStmt                          *sql.Stmt
	registerInsertStmt                          *sql.Stmt
	registerUpdateStmt                          *sql.Stmt
	accountTokenUserStmt                        *sql.Stmt
	token                                       string
	bootstrapToken                              string
	tokenKey                                    []byte
	network                                     *net.IPNet
	ttl                                         int64
	auto                                        int // 0 selects ceil(sqrt(eligible cone relays)); a positive value is an override.
	backboneDegree, clientLinks, symmetricLinks int
	dnsUpstream                                 string
	configMu                                    sync.RWMutex
	inviteMu                                    sync.Mutex
	inviteAttempts                              map[string][]time.Time
	accountMu                                   sync.Mutex
	accountAttempts                             map[string][]time.Time

	sessionsMu          sync.Mutex
	sessions            map[string]map[string]*rendezvousPeer
	registerMu          sync.Mutex
	controlMu           sync.Mutex
	controls            map[*controlClient]string
	controlSessions     atomic.Uint64
	symmetricMu         sync.Mutex
	symmetricRendezvous map[string]symmetricRendezvous
	metricsMu           sync.RWMutex
	metrics             map[string]linkMetric
	updateMu            sync.Mutex
	updateResults       map[string]updateResult
	topologyMu          sync.Mutex
	linkCache           map[string]cachedLinks
	cacheEpoch          uint64
	metricStamp         atomic.Uint64

	// Admin push channel (SSE). See broadcast/adminStream below.
	sseMu      sync.Mutex
	sseClients map[chan []byte]struct{}
	sseDirty   map[string]bool
	sseTimer   *time.Timer
}

type symmetricRendezvous struct {
	source  string
	target  string
	expires time.Time
}

type cachedLinks struct {
	epoch uint64
	links []link
}
type linkMetric struct {
	RTTMS    float64
	LossRate float64
	Up       bool
	ViaLAN   bool
	Seen     time.Time
}

// updateResult is the last self-update report a node delivered. Kept in
// memory only: the node re-registers after a successful restart, and failed
// attempts stay visible until the coordinator restarts.
type updateResult struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	GoArch string `json:"goarch,omitempty"`
	At     int64  `json:"at"`
}

// updateBinaryInfo describes one binary stored on the coordinator. Path is
// resolved by the node against its own configured coordinator URL, so the
// update works behind reverse proxies and NAT without extra configuration.
type updateBinaryInfo struct {
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	UpdatedAt int64  `json:"updated_at"`
	Path      string `json:"path"`
}

// updateSources is the payload of the "update" control event. A node picks
// the entry matching runtime.GOOS/GOARCH; uploaded binaries win over links.
type updateSources struct {
	Binaries map[string]updateBinaryInfo `json:"binaries,omitempty"`
	URLs     map[string]string           `json:"urls,omitempty"`
}

// updateMaxBinaryBytes bounds one uploaded client binary. UPX-compressed
// mesh-node builds are a few megabytes; the cap leaves headroom for
// uncompressed builds without letting an admin fill the disk by accident.
const updateMaxBinaryBytes = 128 << 20

type controlClient struct {
	ws   sync.Mutex
	auth sync.RWMutex
	c    *websocket.Conn
	// session is the connection's accept order. When the same node id
	// registers on two overlapping connections, the newer session owns the
	// binding; the older one must never tear the newer one down.
	session    uint64
	invited    bool
	invite     string
	credential string
}

func (c *controlClient) authState() (credential, invite string, invited bool) {
	c.auth.RLock()
	defer c.auth.RUnlock()
	return c.credential, c.invite, c.invited
}

func (c *controlClient) finishInvite(token string) {
	c.auth.Lock()
	defer c.auth.Unlock()
	if token != "" {
		c.credential = token
	}
	c.invite = ""
	c.invited = false
}

type rendezvousPeer struct {
	endpoint string
	natType  string
	status   string
	other    string
	otherNAT string
	ready    chan struct{}
	created  time.Time
}

// The legacy punch endpoints are unauthenticated by design. Both bounds keep
// an attacker from growing the process heap with never-matched sessions: a
// session is dropped after this TTL and the total number of live sessions is
// capped (re-registering an existing session ID still works).
const (
	rendezvousSessionTTL   = 15 * time.Minute
	rendezvousMaxSessions  = 65536
	inviteEnrollmentWindow = 10 * time.Minute
	controlMaxFrameBytes   = 64 << 10
	controlIdleReadTimeout = 150 * time.Second
)
