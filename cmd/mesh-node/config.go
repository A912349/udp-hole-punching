package main

import (
	"time"
	"net/netip"
	"net"
	"crypto/rand"
	"encoding/hex"
	"crypto/sha256"
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"

	"home-udp-mesh/internal/protocol"
)

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
	f.StringVar(&c.bindIface, "bind-iface", "", "pin UDP sockets to this interface (Linux, root): name, \"auto\" = default-route interface, \"none\" = wildcard; empty = auto on Android, none elsewhere")
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
			if c.bindIface == "" {
				c.bindIface = saved.bindIface
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
		c = config{server: saved.Server, token: saved.Token, inviteToken: saved.InviteToken, role: saved.Role, nat: saved.NAT, bind: saved.Bind, bindIface: saved.BindIface, endpoint: "", meshIP: saved.MeshIP, tun: saved.TUN, state: unifiedStateFile, controlCA: saved.ControlCA, port: saved.Port, capacity: saved.Capacity, prefix: saved.Prefix, symmetricScanStep: step, noRelay: saved.NoRelay, autoTUN: saved.AutoTUN, debug: false, controlInsecure: saved.ControlInsecure}
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
	saved := savedConfig{Server: c.server, Token: c.token, InviteToken: c.inviteToken, Role: c.role, NAT: c.nat, Bind: c.bind, BindIface: c.bindIface, Endpoint: c.endpoint, MeshIP: c.meshIP, TUN: c.tun, State: unifiedStateFile, ControlCA: c.controlCA, Port: c.port, Capacity: c.capacity, Prefix: c.prefix, SymmetricScanStep: c.symmetricScanStep, NoRelay: c.noRelay, AutoTUN: c.autoTUN, Debug: false, ControlInsecure: c.controlInsecure, PrivateKey: privateKey}
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
	c := config{server: ask("Coordinator URL", "http://127.0.0.1:8001"), role: "auto", nat: "auto", bind: "0.0.0.0", state: unifiedStateFile, tun: "mesh0", autoTUN: true, prefix: 24, capacity: 1, symmetricScanStep: symmetricScanDefaultStep, bindIface: ""}
	credential := ask("Network token or 6-character invite", "")
	if len(credential) == 6 {
		c.inviteToken = credential
	} else {
		c.token = credential
	}
	c.role = ask("Role (auto/client/superpeer)", "auto")
	return c
}
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


func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }
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
	if iface := resolveBindIface(c.bindIface); iface != "" {
		if err := bindUDPInterface(conn, iface); err != nil {
			log.Printf("[mesh-node] UDP bind to interface %s failed: %v (using wildcard socket)", iface, err)
		} else {
			log.Printf("[mesh-node] UDP socket pinned to interface %s", iface)
		}
	}
	configureUDPSocket(conn)
	k := sha256.Sum256([]byte(c.token))
	n := &node{
		c:                      c,
		requestedRole:          c.role,
		requestedNAT:           c.nat,
		id:                     id,
		idBinary:               idBinary,
		key:                    k[:],
		conn:                   conn,
		symmetricConns:         make(map[string]*net.UDPConn, 4),
		receiveSockets:         make(map[*net.UDPConn]struct{}, 4),
		dir:                    make(map[string]*peer, 8),
		pendingLAN:             make(map[string]*net.UDPAddr, 4),
		neighbors:              make(map[string]*peer, 8),
		routes:                 make(map[string]string, 8),
		altRoutes:              make(map[string]string, 8),
		meshNodes:              make(map[netip.Addr]string, 16),
		installedRoutes:        make(map[string]bool, 8),
		seen:                   make(map[string]struct{}, 256),
		fastSeen:               make(map[[12]byte]struct{}, fastSeenCapacity),
		fastSeenRing:           make([][12]byte, 0, fastSeenCapacity),
		pending:                map[string]chan serviceResult{},
		services:               make(map[string]string, 4),
		allow:                  map[string]bool{"*": true},
		forwardListeners:       make(map[int64]net.Listener, 4),
		forwardRules:           make(map[int64]portForward, 4),
		tunnels:                make(map[string]net.Conn, 8),
		startedAt:              time.Now(),
		sharedKeys:             make(map[string]cachedKey, 8),
		reassembly:             make(map[string]*reassembly, 4),
		symmetricScans:         map[string]chan struct{}{},
		symmetricSessions:      make(map[string]string, 4),
		symmetricAckWaiters:    map[string]chan struct{}{},
		symmetricConnected:     make(map[string]bool, 4),
		symmetricBurstAt:       make(map[string]time.Time, 4),
		symmetricBurstSess:     make(map[string]string, 4),
		symmetricScanSlots:     make(chan struct{}, 2),
		symmetricBurstInFlight: make(map[string]*symmetricBurstCall, 4),
		symmetricFailures:      make(map[string]int, 4),
		symmetricBackoff:       make(map[string]time.Time, 4),
		edgeRetries:            map[string]bool{},
		pings:                  map[string]pingProbe{},
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
