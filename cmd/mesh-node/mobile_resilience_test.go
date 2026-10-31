package main

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestWWANInterfaceName(t *testing.T) {
	cases := map[string]bool{
		"rmnet_data1": true,
		"rmnet0":      true,
		"ccmni0":      true,
		"pdp_ip0":     true,
		"wwan0":       true,
		"RMNET_DATA2": true,
		"wlan0":       false,
		"eth0":        false,
		"tun0":        false, // classified by virtualInterfaceName instead
		"enp3s0":      false,
	}
	for name, want := range cases {
		if got := wwanInterfaceName(name); got != want {
			t.Fatalf("wwanInterfaceName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestResolveBindIface(t *testing.T) {
	origAndroid, origRoute := androidRuntimeFn, defaultRouteInterfaceFn
	defer func() { androidRuntimeFn, defaultRouteInterfaceFn = origAndroid, origRoute }()

	androidRuntimeFn = func() bool { return true }
	defaultRouteInterfaceFn = func() string { return "rmnet_data1" }

	if got := resolveBindIface(""); got != "rmnet_data1" {
		t.Fatalf("empty config on Android must resolve to the default-route interface, got %q", got)
	}
	if got := resolveBindIface("auto"); got != "rmnet_data1" {
		t.Fatalf("auto must resolve to the default-route interface, got %q", got)
	}
	if got := resolveBindIface("none"); got != "" {
		t.Fatalf("none must force the wildcard socket, got %q", got)
	}
	if got := resolveBindIface("wlan0"); got != "wlan0" {
		t.Fatalf("explicit interface must pass through, got %q", got)
	}

	androidRuntimeFn = func() bool { return false }
	if got := resolveBindIface(""); got != "" {
		t.Fatalf("empty config on desktop must keep the wildcard socket, got %q", got)
	}
	if got := resolveBindIface("auto"); got != "rmnet_data1" {
		t.Fatalf("explicit auto must resolve everywhere, got %q", got)
	}
}

func TestSymmetricBackoffGrowsAndResets(t *testing.T) {
	n := &node{id: &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"}}
	relay := "0123456789abcdef0123456789abcdef"

	if wait := n.symmetricBackoffWait(relay); wait != 0 {
		t.Fatalf("fresh relay must not be backed off, got %v", wait)
	}

	n.symmetricBurstFailed(relay)
	n.symmetricBurstFailed(relay)
	wait := n.symmetricBackoffWait(relay)
	if wait <= 0 || wait > 8*symmetricRetryDelay {
		t.Fatalf("two failures must back off ~4x%v, got %v", symmetricRetryDelay, wait)
	}
	before := wait
	n.symmetricBurstFailed(relay)
	if n.symmetricBackoffWait(relay) <= before {
		t.Fatal("backoff must grow with each consecutive failure")
	}

	n.symmetricBurstSucceeded(relay)
	if wait := n.symmetricBackoffWait(relay); wait != 0 {
		t.Fatalf("success must clear the backoff, got %v", wait)
	}
}

func TestSymmetricBurstJoinsInFlightScan(t *testing.T) {
	relay := "0123456789abcdef0123456789abcdef"
	n := &node{
		id:                     &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		c:                      config{nat: "symmetric"},
		symmetricBurstInFlight: map[string]*symmetricBurstCall{},
	}
	call := &symmetricBurstCall{done: make(chan struct{}), ok: true}
	n.symmetricBurstInFlight[relay] = call
	close(call.done)

	start := time.Now()
	ok := n.establishSymmetricTransportOnce(relay, &peer{Endpoint: "127.0.0.1:1"}, 1)
	if !ok {
		t.Fatal("joiner must inherit the in-flight scan outcome")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("joiner must not start its own burst, took %v", elapsed)
	}
}

func TestSymmetricEdgeNeedsRescanDespiteInstalledTransport(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("no UDP socket: %v", err)
	}
	defer conn.Close()
	relay := "d8da7f47d8da7f47d8da7f47d8da7f47"
	n := &node{
		id:              &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		c:               config{nat: "symmetric"},
		neighbors:       map[string]*peer{relay: {ID: relay, Role: "superpeer", Endpoint: "10.0.0.1:40000", lastRX: time.Now().Add(-2 * linkTimeout)}},
		symmetricConns:  map[string]*net.UDPConn{relay: conn},
		symmetricConnMu: sync.RWMutex{},
	}
	// Regression: the punched transport socket lingers after the relay went
	// silent (link down), and treating its mere presence as "ready" blocked
	// all retries — the edge stayed down forever.
	if !n.symmetricEdgeNeedsRescan(relay) {
		t.Fatal("installed but silent transport must not block a rescan")
	}
	// Fresh traffic means the edge recovered; no rescan needed.
	n.mu.Lock()
	n.neighbors[relay].lastRX = time.Now()
	n.mu.Unlock()
	if n.symmetricEdgeNeedsRescan(relay) {
		t.Fatal("edge with fresh traffic must not be rescanned")
	}
	// A traffic-confirmed LAN path also suppresses the burst (hairpin).
	n.mu.Lock()
	p := n.neighbors[relay]
	p.lastRX = time.Time{}
	p.lastLAN = copyUDPAddr(&net.UDPAddr{IP: net.ParseIP("192.168.1.35"), Port: 47959})
	p.lastLANRX = time.Now()
	n.mu.Unlock()
	if n.symmetricEdgeNeedsRescan(relay) {
		t.Fatal("traffic-confirmed LAN path must not trigger a rescan")
	}
}

func TestResetSymmetricRelayKeepsPrimary(t *testing.T) {
	primary, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("no UDP socket: %v", err)
	}
	defer primary.Close()
	secondary, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("no UDP socket: %v", err)
	}
	defer secondary.Close()

	relayA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	relayB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	n := &node{
		id:                 &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		c:                  config{nat: "symmetric", bind: "127.0.0.1"},
		symmetricConns:     map[string]*net.UDPConn{relayA: primary, relayB: secondary},
		symmetricConnMu:    sync.RWMutex{},
		conn:               primary,
		connMu:             sync.RWMutex{},
		symmetricScans:     map[string]chan struct{}{},
		symmetricSessions:  map[string]string{},
		symmetricConnected: map[string]bool{},
		symmetricBurstAt:   map[string]time.Time{},
		symmetricBurstSess: map[string]string{},
		symmetricMu:        sync.Mutex{},
	}

	// Resetting the secondary must not touch the primary.
	n.resetSymmetricRelay(relayB)
	if n.currentUDPConn() != primary {
		t.Fatal("primary socket must survive a secondary relay reset")
	}
	if _, ok := n.symmetricConns[relayB]; ok {
		t.Fatal("secondary transport must be removed")
	}

	// Resetting a relay without any transport must not disturb the primary
	// either (retry path after a failed scan).
	n.resetSymmetricRelay(relayB)
	if n.currentUDPConn() != primary {
		t.Fatal("primary socket must survive resetting an absent relay")
	}
	if _, err := primary.WriteToUDP([]byte{0}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}); err != nil {
		t.Fatalf("primary socket must stay usable: %v", err)
	}
}

func TestLanCandidateUsable(t *testing.T) {
	now := time.Now()
	withLAN := func() *node {
		return &node{
			id:             &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
			lanSubnetCache: []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")},
			lanSubnetsAt:   now,
			subnets:        []netip.Prefix{netip.MustParsePrefix("192.168.77.0/24")},
			subnetsAt:      now,
		}
	}

	n := withLAN()
	if !n.lanCandidateUsable(net.ParseIP("192.168.77.20")) {
		t.Fatal("private candidate inside the local LAN must be usable")
	}
	// A private candidate outside the own subnet stays probeable while a
	// LAN exists: this is the cascaded-router discovery case (adjacent
	// subnet of the same physical network). The cost is one HELLO per
	// lanProbeInterval.
	if !n.lanCandidateUsable(net.ParseIP("192.168.2.118")) {
		t.Fatal("private candidate from an adjacent subnet must stay probeable on Wi-Fi")
	}

	// Mobile data: no local LAN at all.
	n = &node{
		id:             &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		lanSubnetCache: []netip.Prefix{},
		lanSubnetsAt:   now,
		subnets:        []netip.Prefix{},
		subnetsAt:      now,
	}
	if n.lanCandidateUsable(net.ParseIP("192.168.2.118")) {
		t.Fatal("private candidates must not be probed without a local LAN")
	}

	// Exotic public LAN range is usable only from inside the same subnet.
	n = withLAN()
	n.subnets = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if !n.lanCandidateUsable(net.ParseIP("203.0.113.9")) {
		t.Fatal("candidate inside an own subnet must be usable")
	}
	if n.lanCandidateUsable(net.ParseIP("203.0.114.9")) {
		t.Fatal("public candidate outside own subnets must not be probed")
	}
}

func TestAdvertisedLanAddrsFiltersCarrierRanges(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("no UDP socket: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	n := &node{
		id:     &protocol.Identity{ID: "fedcba9876543210fedcba9876543210"},
		conn:   conn,
		connMu: sync.RWMutex{},
		// Cached subnets as they look on a phone: a real LAN plus a public
		// carrier range (10.x carrier-internal ranges are excluded earlier
		// by the wwan interface filter in collectSubnets).
		lanSubnetCache: []netip.Prefix{
			netip.MustParsePrefix("192.168.77.111/24"),
			netip.MustParsePrefix("33.57.14.58/29"),
		},
		lanSubnetsAt: time.Now(),
	}
	addrs := n.advertisedLanAddrs()
	if len(addrs) != 1 {
		t.Fatalf("only the genuine LAN address must be advertised, got %v", addrs)
	}
	want := net.JoinHostPort("192.168.77.111", strconv.Itoa(port))
	if addrs[0] != want {
		t.Fatalf("advertised address = %v, want %v", addrs[0], want)
	}

	// A phone on mobile data only must not advertise anything.
	n.lanSubnetCache = []netip.Prefix{}
	if addrs := n.advertisedLanAddrs(); len(addrs) != 0 {
		t.Fatalf("mobile-data node must not advertise LAN addresses, got %v", addrs)
	}
}
