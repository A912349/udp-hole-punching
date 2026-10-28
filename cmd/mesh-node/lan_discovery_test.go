package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

func TestBroadcastForPrefix(t *testing.T) {
	cases := []struct {
		prefix netip.Prefix
		want   string
		ok     bool
	}{
		{netip.MustParsePrefix("192.168.1.100/24"), "192.168.1.255", true},
		{netip.MustParsePrefix("10.0.5.7/8"), "10.255.255.255", true},
		{netip.MustParsePrefix("172.16.4.1/16"), "172.16.255.255", true},
		{netip.MustParsePrefix("192.168.0.1/30"), "192.168.0.3", true},
		// Point-to-point and host routes have no broadcast address.
		{netip.MustParsePrefix("10.0.0.1/31"), "", false},
		{netip.MustParsePrefix("10.0.0.1/32"), "", false},
		{netip.MustParsePrefix("0.0.0.0/0"), "", false},
	}
	for _, c := range cases {
		got, ok := broadcastForPrefix(c.prefix)
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Fatalf("broadcastForPrefix(%s) = %s, %v; want %s, %v", c.prefix, got, ok, c.want, c.ok)
		}
	}
}

func TestVirtualInterfaceName(t *testing.T) {
	virtual := []string{
		"lo", "lo0", "docker0", "br-a1b2c3d4e5f6", "veth9f3c21", "virbr0",
		"vmnet1", "vboxnet0", "vEthernet (WSL)", "vEthernet (Default Switch)",
		"VirtualBox Host-Only Network", "VMware Network Adapter VMnet8",
		"Tailscale", "ztly5uqzve-0", "tun0", "utun3", "tap0", "wg0", "ifb0",
		"dummy0", "Loopback Pseudo-Interface 1", "Bluetooth Device (PAN)",
	}
	for _, name := range virtual {
		if !virtualInterfaceName(name) {
			t.Fatalf("%q must be classified as virtual", name)
		}
	}
	physical := []string{
		"eth0", "eth1", "enp3s0", "wlan0", "wlp2s0", "br-lan", "br-wan",
		"Ethernet", "Ethernet 2", "Wi-Fi", "Local Area Connection",
		"lan", "wan", "eth0.100",
	}
	for _, name := range physical {
		if virtualInterfaceName(name) {
			t.Fatalf("%q must not be classified as virtual", name)
		}
	}
}

func TestIsMeshAddrExcludesOverlaySubnet(t *testing.T) {
	n := &node{}
	n.meshIPv4.Store(0x0a420001) // 10.66.0.1
	n.c.prefix = 24
	if !n.isMeshAddr(netip.MustParseAddr("10.66.0.99")) {
		t.Fatal("an overlay address must be excluded from LAN candidates")
	}
	if n.isMeshAddr(netip.MustParseAddr("192.168.1.50")) {
		t.Fatal("a physical LAN address must never be treated as overlay")
	}
}

func TestMeshHasOtherNodes(t *testing.T) {
	id, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	lone := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), nil)
	if lone.meshHasOtherNodes() {
		t.Fatal("a lone node must not broadcast")
	}
	// Different external IP: the old same-NAT gate disabled discovery here,
	// although both nodes can share one physical LAN (multi-WAN routers,
	// stale endpoints, NAT detection lagging at startup).
	lone.dir["other"] = &peer{ID: "other", Endpoint: "203.0.113.9:40000"}
	if !lone.meshHasOtherNodes() {
		t.Fatal("a mesh with another node must broadcast regardless of NAT match")
	}
}

// A candidate LAN address that never answered must be re-probed by every
// keepalive instead of waiting for the 30-second probe round.
func TestPingAllProbesUnconfirmedLANCandidate(t *testing.T) {
	id, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer sink.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer conn.Close()

	n := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), conn)
	n.seen = map[string]struct{}{}
	n.pings = map[string]pingProbe{}
	lan := copyUDPAddr(sink.LocalAddr().(*net.UDPAddr))
	// The public endpoint must stay reachable so a failed send cannot spawn
	// retryDeadEdge, which would race JSON HELLOs into the same sink.
	public, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer public.Close()
	n.neighbors[peerID.ID] = &peer{ID: peerID.ID, Endpoint: public.LocalAddr().String(), lastLAN: lan}

	n.pingAll()

	_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	length, _, err := sink.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no keepalive arrived at the LAN candidate: %v", err)
	}
	packet, err := protocol.DecodeCompact(buf[:length], n.key)
	if err != nil || packet.Type != "PING" || packet.Source != id.ID || packet.Destination != peerID.ID {
		t.Fatalf("unexpected packet at LAN candidate: decode=%v packet=%+v", err, packet)
	}
}

// A traffic-confirmed LAN path receives exactly one keepalive: no duplicate
// to the same address, and none to the public endpoint.
func TestPingAllSkipsDuplicateWhenLANConfirmed(t *testing.T) {
	id, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer sink.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback UDP unavailable: %v", err)
	}
	defer conn.Close()

	n := newBenchNode(id, &benchTUN{}, netip.MustParseAddr("10.77.0.5"), conn)
	n.seen = map[string]struct{}{}
	n.pings = map[string]pingProbe{}
	now := time.Now()
	lan := copyUDPAddr(sink.LocalAddr().(*net.UDPAddr))
	n.neighbors["peer"] = &peer{
		ID: "peer", Endpoint: "93.0.0.1:40000",
		last: lan, lastLAN: lan, lastLANRX: now, lastPathLAN: true, lastRX: now, up: true,
	}

	n.pingAll()

	_ = sink.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	if _, _, err := sink.ReadFromUDP(buf); err != nil {
		t.Fatalf("confirmed LAN path must still receive keepalives: %v", err)
	}
	// One PING total: no datagram may be left queued for a duplicate read.
	_ = sink.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := sink.ReadFromUDP(buf); err == nil {
		t.Fatal("traffic-confirmed LAN path must not receive a duplicated keepalive")
	}
}
