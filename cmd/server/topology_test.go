package main

import "testing"
import "net/netip"

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
