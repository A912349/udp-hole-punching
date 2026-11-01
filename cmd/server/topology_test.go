package main

import (
	"fmt"
	"home-udp-mesh/internal/protocol"
	"math"
	"net/netip"
	"testing"
	"time"
)

func almostEqualCost(a, b float64) bool {
	d := math.Abs(a - b)
	return d < 1e-9
}

func TestDecorateLinksCostModel(t *testing.T) {
	now := time.Now()
	up := func(rtt, loss float64) linkMetric {
		return linkMetric{RTTMS: rtt, LossRate: loss, Up: true, Seen: now}
	}
	s := &server{metrics: map[string]linkMetric{
		metricKey("a", "b"): up(20, 0), // healthy fast WAN
		metricKey("b", "a"): up(20, 0),
		metricKey("c", "d"): up(300, 0), // slow WAN
		metricKey("d", "c"): up(300, 0),
		metricKey("e", "f"): up(600000, 0), // absurd probe: must be capped
		metricKey("f", "e"): up(600000, 0),
		metricKey("g", "h"): up(20, 0.5), // lossy in one direction
		metricKey("h", "g"): up(20, 0.1),
		metricKey("i", "j"): {RTTMS: 20, Up: true, ViaLAN: true, Seen: now},
		metricKey("j", "i"): {RTTMS: 20, Up: true, ViaLAN: true, Seen: now},
		metricKey("k", "l"): {RTTMS: 20, Up: false, Seen: now}, // down
		metricKey("l", "k"): up(20, 0),
	}}
	links := s.decorateLinks([]link{
		{A: "a", B: "b", Cost: 1},
		{A: "c", B: "d", Cost: 1},
		{A: "e", B: "f", Cost: 1},
		{A: "g", B: "h", Cost: 1},
		{A: "i", B: "j", Cost: 1},
		{A: "k", B: "l", Cost: 1},
		{A: "m", B: "n", Cost: 1}, // no telemetry at all
	})
	byEdge := map[string]link{}
	for _, l := range links {
		byEdge[l.A+"-"+l.B] = l
	}
	cost := func(e string) float64 { return byEdge[e].Cost }
	// 20 ms against a 100 ms reference: 1.2x, status up.
	if !almostEqualCost(cost("a-b"), 1.2) || byEdge["a-b"].Status != "up" {
		t.Fatalf("healthy WAN edge: cost=%v status=%s, want 1.2/up", cost("a-b"), byEdge["a-b"].Status)
	}
	// 300 ms: 4x — slow paths must lose ties against healthy alternates.
	if !almostEqualCost(cost("c-d"), 4.0) {
		t.Fatalf("slow WAN edge cost = %v, want 4", cost("c-d"))
	}
	// One absurd probe is capped at 6x instead of pricing the edge out.
	if !almostEqualCost(cost("e-f"), 6.0) {
		t.Fatalf("capped RTT cost = %v, want 6", cost("e-f"))
	}
	// Loss is ETX-style on the worse direction: 1.2 * 1/(1-0.5) = 2.4.
	if !almostEqualCost(cost("g-h"), 2.4) || !almostEqualCost(byEdge["g-h"].Loss, 0.5) {
		t.Fatalf("lossy edge: cost=%v loss=%v, want 2.4/0.5", cost("g-h"), byEdge["g-h"].Loss)
	}
	// Both-direction confirmed LAN path gets the bandwidth discount.
	if !almostEqualCost(cost("i-j"), 0.6) || !byEdge["i-j"].ViaLAN {
		t.Fatalf("LAN edge: cost=%v viaLAN=%v, want 0.6/true", cost("i-j"), byEdge["i-j"].ViaLAN)
	}
	// Down state: 1.2 * 4.
	if !almostEqualCost(cost("k-l"), 4.8) || byEdge["k-l"].Status != "down" {
		t.Fatalf("down edge: cost=%v status=%s, want 4.8/down", cost("k-l"), byEdge["k-l"].Status)
	}
	// Unknown state: base 2x and no invented RTT.
	if !almostEqualCost(cost("m-n"), 2.0) || byEdge["m-n"].Status != "unknown" || byEdge["m-n"].RTTMS != 0 {
		t.Fatalf("unknown edge: %+v, want cost 2/unknown/no rtt", byEdge["m-n"])
	}
}

func TestUpdateLinkMetricsLossBands(t *testing.T) {
	s := &server{metrics: map[string]linkMetric{}}
	if !s.updateLinkMetrics("a", []protocol.LinkMeasurement{{PeerID: "b", Loss: 0.4}}) {
		t.Fatal("first sighting of heavy loss must invalidate the topology cache")
	}
	if got := s.metrics[metricKey("a", "b")].LossRate; got != 0.4 {
		t.Fatalf("loss rate = %v, want 0.4", got)
	}
	// Jitter around the stored value stays inside one band: no rebuild.
	for i := 0; i < 3; i++ {
		if s.updateLinkMetrics("a", []protocol.LinkMeasurement{{PeerID: "b", Loss: 0.45}}) {
			t.Fatal("jitter inside a loss band must not invalidate the topology cache")
		}
	}
	// Sustained recovery decays the estimate across a band boundary.
	if !s.updateLinkMetrics("a", []protocol.LinkMeasurement{{PeerID: "b"}}) {
		t.Fatal("decay across a loss band boundary must invalidate the topology cache")
	}
	if got := s.metrics[metricKey("a", "b")].LossRate; got >= 0.3 {
		t.Fatalf("loss rate must decay, got %v", got)
	}
}

func TestVirtualSubnetAllocationAvoidsDuplicatePhysicalLANs(t *testing.T) {
	mesh := netip.MustParsePrefix("10.77.0.0/24")
	first := allocateVirtual(24, []netip.Prefix{mesh})
	if first != "10.77.1.0/24" {
		t.Fatalf("first allocation = %s", first)
	}
	second := allocateVirtual(24, []netip.Prefix{mesh, netip.MustParsePrefix(first)})
	if second != "10.77.2.0/24" {
		t.Fatalf("second allocation = %s", second)
	}
}

func TestObjectAddressUsesVirtualPrefix(t *testing.T) {
	routes := []routeAdvertisement{{LAN: "192.168.1.0/24", Virtual: "10.77.9.0/24"}}
	if got := translatedIP("192.168.1.42", routes, true); got != "10.77.9.42" {
		t.Fatalf("translated object = %s", got)
	}
}

func testNode(id, nat, role string, capacity int) node {
	return node{ID: id, NAT: nat, Role: role, Capacity: capacity}
}

func neighborsFor(ls []link, id string) map[string]bool {
	out := map[string]bool{}
	for _, l := range ls {
		if l.A == id {
			out[l.B] = true
		}
		if l.B == id {
			out[l.A] = true
		}
	}
	return out
}

func TestTieredTopologyClientRedundancy(t *testing.T) {
	s := &server{backboneDegree: 6, clientLinks: 2, symmetricLinks: 3}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 2),
		testNode("sp-c", "cone", "superpeer", 1),
		testNode("mobile", "symmetric", "client", 1),
		testNode("desktop", "cone", "client", 1),
	}
	ls := s.links(nodes)
	if got := len(neighborsFor(ls, "mobile")); got != 3 {
		t.Fatalf("symmetric client has %d links, want 3", got)
	}
	if got := len(neighborsFor(ls, "desktop")); got != 2 {
		t.Fatalf("cone client has %d links, want 2", got)
	}
}

func TestWeightedPeerOrderIsStable(t *testing.T) {
	client := testNode("mobile", "symmetric", "client", 1)
	peers := []node{testNode("sp-a", "cone", "superpeer", 1), testNode("sp-b", "cone", "superpeer", 2)}
	first := weightedPeerOrder(client, peers)
	second := weightedPeerOrder(client, peers)
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatal("peer order changed without a topology change")
		}
	}
}

func TestRebalanceRolesDoesNotRewriteStableRoles(t *testing.T) {
	s := testAuthServer(t)
	now := time.Now().Unix()
	for _, n := range []struct {
		id, role, requested string
	}{
		{"superpeer", "superpeer", "superpeer"},
		{"client", "client", "client"},
	} {
		meshIP := "10.77.0.10"
		if n.id == "client" {
			meshIP = "10.77.0.11"
		}
		if _, err := s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			n.id, "public-"+n.id, "cone", n.role, "127.0.0.1:10000", n.requested, 1, 1, now, now, meshIP); err != nil {
			t.Fatal(err)
		}
	}
	var before, after int64
	if err := s.db.QueryRow("SELECT total_changes()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := s.rebalanceRoles(); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT total_changes()").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("stable role rebalance made %d unnecessary database writes", after-before)
	}
}

func TestManualBackboneStillAttachesNewClients(t *testing.T) {
	s := &server{clientLinks: 2, symmetricLinks: 3}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("new-client", "cone", "client", 1),
	}
	links := s.addAutomaticClientLinks([]link{{A: "sp-a", B: "sp-b"}}, nodes, superpeerNodes(nodes), nil)
	if got := len(neighborsFor(links, "new-client")); got != 2 {
		t.Fatalf("new client has %d automatic superpeer links, want 2", got)
	}
}

func TestBackboneDegreeOneStaysConnected(t *testing.T) {
	s := &server{backboneDegree: 1, clientLinks: 2, symmetricLinks: 3}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("sp-c", "cone", "superpeer", 1),
		testNode("sp-d", "cone", "superpeer", 1),
		testNode("sp-e", "cone", "superpeer", 1),
		testNode("sp-f", "cone", "superpeer", 1),
		testNode("sp-g", "cone", "superpeer", 1),
	}
	// backboneDegree=1 used to emit a perfect matching (even peer count) or
	// no backbone at all (odd peer count): a silently partitioned mesh.
	for _, count := range []int{2, 3, 4, 5, 6, 7} {
		ls := s.links(nodes[:count])
		if !connected(ls, nodes[:count]) {
			t.Fatalf("backbone of %d superpeers with degree=1 is disconnected", count)
		}
	}
}

func TestBackboneSurvivesSingleSuperpeerLoss(t *testing.T) {
	s := &server{backboneDegree: 2, clientLinks: 2, symmetricLinks: 3}
	sp := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("sp-c", "cone", "superpeer", 1),
		testNode("sp-d", "cone", "superpeer", 1),
		testNode("sp-e", "cone", "superpeer", 1),
	}
	for drop := range sp {
		remaining := append(append([]node(nil), sp[:drop]...), sp[drop+1:]...)
		ls := s.links(remaining)
		if !connected(ls, remaining) {
			t.Fatalf("backbone disconnected after losing %s", sp[drop].ID)
		}
	}
}

func TestGraphStaysConnectedWhenSuperpeerLeaves(t *testing.T) {
	s := &server{backboneDegree: 2, clientLinks: 2, symmetricLinks: 3}
	full := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("c-1", "cone", "client", 1),
		testNode("c-2", "cone", "client", 1),
		testNode("c-3", "symmetric", "client", 1),
	}
	if !connected(s.links(full), full) {
		t.Fatal("full mesh is disconnected")
	}
	// The remaining superpeer keeps every client attached; nobody strands.
	left := []node{full[1], full[2], full[3], full[4]}
	ls := s.links(left)
	if !connected(ls, left) {
		t.Fatal("mesh disconnected after the superpeer left")
	}
	for _, n := range left {
		if len(neighborsFor(ls, n.ID)) == 0 {
			t.Fatalf("%s has no neighbors after the superpeer left", n.ID)
		}
	}
}

func TestPureClientMeshWithoutSuperpeersStaysConnected(t *testing.T) {
	s := &server{backboneDegree: 6, clientLinks: 2, symmetricLinks: 3}
	nodes := []node{
		testNode("n-1", "symmetric", "client", 1),
		testNode("n-2", "symmetric", "client", 1),
		testNode("n-3", "symmetric", "client", 1),
	}
	// Before the fallback this produced zero links: after the last relay
	// node left, the whole mesh went dark.
	ls := s.links(nodes)
	if !connected(ls, nodes) {
		t.Fatal("pure-client mesh must degrade to peer-to-peer, not an empty graph")
	}
	for _, n := range nodes {
		if len(neighborsFor(ls, n.ID)) == 0 {
			t.Fatalf("%s has no neighbors in a superpeerless mesh", n.ID)
		}
	}
}

func TestManualIslandsAreBridged(t *testing.T) {
	s := &server{clientLinks: 1, symmetricLinks: 1}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("sp-c", "cone", "superpeer", 1),
		testNode("sp-d", "cone", "superpeer", 1),
	}
	links := s.ensureConnected([]link{{A: "sp-a", B: "sp-b"}, {A: "sp-c", B: "sp-d"}}, nodes, nil)
	if !connected(links, nodes) {
		t.Fatal("manual islands were not bridged")
	}
	// A superpeer-to-superpeer bridge is preferred over client endpoints.
	bridged := false
	for _, e := range links {
		if (e.A == "sp-b" && e.B == "sp-c") || (e.A == "sp-a" && e.B == "sp-c") ||
			(e.A == "sp-b" && e.B == "sp-d") || (e.A == "sp-a" && e.B == "sp-d") {
			bridged = true
		}
	}
	if !bridged {
		t.Fatalf("bridge should connect superpeers directly, got %v", links)
	}
}

func TestEnsureConnectedIsStableAcrossRebuilds(t *testing.T) {
	s := &server{clientLinks: 1, symmetricLinks: 1}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 2),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("c-1", "cone", "client", 1),
		testNode("c-2", "cone", "client", 1),
	}
	edges := []link{{A: "sp-a", B: "sp-b"}}
	first := s.ensureConnected(append([]link(nil), edges...), nodes, nil)
	second := s.ensureConnected(append([]link(nil), edges...), nodes, nil)
	if len(first) != len(second) {
		t.Fatalf("repair added %d then %d edges", len(first), len(second))
	}
	for i := range first {
		if first[i].A != second[i].A || first[i].B != second[i].B {
			t.Fatalf("repair is not deterministic: %v vs %v", first, second)
		}
	}
}

func TestBlockedFirstChoiceDoesNotIsolateClient(t *testing.T) {
	s := testAuthServer(t)
	defer s.db.Close()
	now := time.Now().Unix()
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
		testNode("client", "cone", "client", 1),
	}
	for i, n := range nodes {
		if _, err := s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			n.ID, "key-"+n.ID, "cone", n.Role, "127.0.0.1:10000", "auto", 1, 1, now, now, fmt.Sprintf("10.77.0.%d", i+10)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("INSERT INTO graph_blocks(a,b) VALUES(?,?)", "client", "sp-a"); err != nil {
		t.Fatal(err)
	}
	// rendezvous would pick sp-a first; the blocked edge must shift the
	// attachment to sp-b instead of leaving the client with one link fewer.
	rank := weightedPeerOrder(nodes[2], []node{nodes[0], nodes[1]})
	if rank[0].ID == "sp-a" {
		ls := s.links(nodes)
		if got := len(neighborsFor(ls, "client")); got != 1 {
			t.Fatalf("blocked first choice cost the client links: %d", got)
		}
	}
}

func TestEnsureConnectedRespectsBlocks(t *testing.T) {
	s := &server{clientLinks: 1, symmetricLinks: 1}
	nodes := []node{
		testNode("sp-a", "cone", "superpeer", 1),
		testNode("sp-b", "cone", "superpeer", 1),
	}
	blocked := map[string]bool{edgeKey("sp-a", "sp-b"): true}
	out := s.ensureConnected(nil, nodes, blocked)
	for _, e := range out {
		if edgeKey(e.A, e.B) == edgeKey("sp-a", "sp-b") {
			t.Fatal("repair restored an explicitly blocked edge")
		}
	}
	// Without the block the same components are bridged.
	if len(s.ensureConnected(nil, nodes, nil)) != 1 {
		t.Fatal("unblocked components were not bridged")
	}
}

func connected(ls []link, nodes []node) bool {
	if len(nodes) < 2 {
		return true
	}
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		for parent[x] != x {
			x = parent[x]
		}
		return x
	}
	for _, n := range nodes {
		parent[n.ID] = n.ID
	}
	for _, e := range ls {
		a, b := find(e.A), find(e.B)
		if a != b {
			parent[a] = b
		}
	}
	root := find(nodes[0].ID)
	for _, n := range nodes[1:] {
		if find(n.ID) != root {
			return false
		}
	}
	return true
}

func TestBlockedAutomaticClientLinkStaysRemoved(t *testing.T) {
	s := testAuthServer(t)
	defer s.db.Close()
	now := time.Now().Unix()
	for i, n := range []struct{ id, role string }{{"sp-a", "superpeer"}, {"sp-b", "superpeer"}, {"client", "client"}} {
		if _, err := s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			n.id, "key-"+n.id, "cone", n.role, "127.0.0.1:10000", "auto", 1, 1, now, now, fmt.Sprintf("10.77.0.%d", i+10)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("INSERT INTO graph_blocks(a,b) VALUES(?,?)", "client", "sp-a"); err != nil {
		t.Fatal(err)
	}
	nodes := []node{testNode("sp-a", "cone", "superpeer", 1), testNode("sp-b", "cone", "superpeer", 1), testNode("client", "cone", "client", 1)}
	if neighborsFor(s.links(nodes), "client")["sp-a"] {
		t.Fatal("blocked automatic client-superpeer link was restored")
	}
	if !neighborsFor(s.links(nodes), "client")["sp-b"] {
		t.Fatal("unblocked automatic client-superpeer link was not retained")
	}
}

func TestRegistrationTopologyChangeIgnoresHeartbeat(t *testing.T) {
	previous := &node{
		PublicKey: "key", NAT: "cone", Role: "client", Endpoint: "198.51.100.1:1000",
		RequestedRole: "auto", Relay: true, Capacity: 1, MeshIP: "10.77.0.2", LastSeen: 100,
	}
	next := *previous
	if registrationChangesTopology(previous, 90, next) {
		t.Fatal("unchanged online registration must be treated as a heartbeat")
	}
	if !registrationChangesTopology(previous, 101, next) {
		t.Fatal("returning from offline must update topology")
	}
	next.Endpoint = "198.51.100.2:1000"
	if !registrationChangesTopology(previous, 90, next) {
		t.Fatal("endpoint change must update topology")
	}
}

func TestBootstrapTopologyVersionCoversEffectiveLinksAndNetworkMetadata(t *testing.T) {
	nodes := []node{{ID: "a", PublicKey: "key-a", MeshIP: "10.77.0.1"}, {ID: "b", PublicKey: "key-b", MeshIP: "10.77.0.2"}}
	base := bootstrapTopologyVersion(nodes, []link{{A: "a", B: "b", Cost: 1}})
	if got := bootstrapTopologyVersion(nodes, []link{{A: "a", B: "b", Cost: 2}}); got == base {
		t.Fatal("link cost change must change bootstrap topology version")
	}
	nodes[0].Routes = []routeAdvertisement{{LAN: "192.168.1.0/24", Virtual: "10.77.1.0/24"}}
	if got := bootstrapTopologyVersion(nodes, []link{{A: "a", B: "b", Cost: 1}}); got == base {
		t.Fatal("route change must change bootstrap topology version")
	}
}

func TestTelemetryPeerOrderIsStableAcrossHealthyRTTNoise(t *testing.T) {
	client := testNode("client", "cone", "client", 1)
	peers := []node{testNode("sp-a", "cone", "superpeer", 1), testNode("sp-b", "cone", "superpeer", 1)}
	expected := weightedPeerOrder(client, peers)
	s := &server{metrics: map[string]linkMetric{
		metricKey(client.ID, "sp-a"): {Up: true, RTTMS: 900, Seen: time.Now()},
		metricKey(client.ID, "sp-b"): {Up: true, RTTMS: 1, Seen: time.Now()},
	}}
	got := s.telemetryPeerOrder(client, peers)
	for i := range expected {
		if got[i].ID != expected[i].ID {
			t.Fatal("healthy RTT noise changed stable peer assignment")
		}
	}
}

func TestTelemetryPeerOrderDemotesConfirmedDirectionalFailure(t *testing.T) {
	client := testNode("client", "cone", "client", 1)
	peers := []node{testNode("sp-a", "cone", "superpeer", 1), testNode("sp-b", "cone", "superpeer", 1)}
	s := &server{metrics: map[string]linkMetric{
		metricKey(client.ID, "sp-a"): {Up: false, Seen: time.Now()},
		// A reverse-direction success must not overwrite the client's failure.
		metricKey("sp-a", client.ID): {Up: true, Seen: time.Now()},
	}}
	got := s.telemetryPeerOrder(client, peers)
	if got[0].ID != "sp-b" {
		t.Fatalf("unknown alternative was not preferred over failed direction: %s", got[0].ID)
	}
}
