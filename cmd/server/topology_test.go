package main

import "testing"
import "net/netip"
import "time"
import "fmt"

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
	if err := s.rebalanceRoles(); err != nil {
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
	links := s.addAutomaticClientLinks([]link{{A: "sp-a", B: "sp-b"}}, nodes)
	if got := len(neighborsFor(links, "new-client")); got != 2 {
		t.Fatalf("new client has %d automatic superpeer links, want 2", got)
	}
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
