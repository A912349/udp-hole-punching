package main

import "testing"

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
