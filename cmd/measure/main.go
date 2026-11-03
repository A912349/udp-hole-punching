package main

import (
	"encoding/json"
	"fmt"
)

type node struct {
	ID   string `json:"node_id"`
	Public string `json:"public_key"`
	NAT  string `json:"nat_type"`
	Role string `json:"role"`
	Endpoint string `json:"endpoint"`
	RequestedRole string `json:"requested_role"`
	Relay bool `json:"relay_capable"`
	Capacity int `json:"capacity"`
	MeshIP string `json:"mesh_ip"`
}

func main() {
	// self + 5 neighbors + 5 other directory nodes (K=5 idle mesh)
	var nodes []node
	for i := 0; i < 11; i++ {
		nodes = append(nodes, node{
			ID: fmt.Sprintf("%032x", uint64(i+1)),
			Public: "B" + fmt.Sprintf("%064x", uint64(i+1)),
			NAT: "symmetric", Role: "client", Endpoint: "203.0.113.7:42000",
			RequestedRole: "auto", Relay: i < 3, Capacity: 1, MeshIP: "10.2.0.5",
		})
	}
	self := nodes[0]
	peers := nodes[1:6] // 5 neighbors
	dir := nodes
	topo := map[string]any{
		"topology_version": "v1-dnsdeadbeef00-f1122334455-g66778899aa",
		"self": self, "neighbors": peers, "directory": dir,
		"backbone_links": []map[string]any{}, "dns_upstream": "1.1.1.1",
		"services": []map[string]string{}, "forwards": []map[string]any{},
		"firewall": map[string]any{"mode": "allow_all"},
	}
	b, _ := json.Marshal(topo)
	fmt.Printf("bootstrap topology response (11 nodes, 5 neighbors) : %d B\n", len(b))
	// smaller mesh: self + 5 neighbors only
	topo2 := map[string]any{
		"topology_version": "v1-dnsdeadbeef00",
		"self": self, "neighbors": peers, "directory": peers,
		"backbone_links": []map[string]any{}, "dns_upstream": "1.1.1.1",
		"services": []map[string]string{}, "forwards": []map[string]any{},
		"firewall": map[string]any{"mode": "allow_all"},
	}
	b2, _ := json.Marshal(topo2)
	fmt.Printf("bootstrap topology response (6 nodes only)         : %d B\n", len(b2))
}
