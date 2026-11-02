package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)


// adminTopology returns the authenticated account’s view of its mesh.

func (s *server) enrichNodes(nodes []node) {
	rows, err := s.db.Query("SELECT node_id,name,routes,dns_ip FROM node_network")
	if err != nil {
		return
	}
	byID := map[string]*node{}
	for i := range nodes {
		byID[nodes[i].ID] = &nodes[i]
	}
	for rows.Next() {
		var id, name, raw, legacyDNS string
		if rows.Scan(&id, &name, &raw, &legacyDNS) != nil {
			continue
		}
		if n := byID[id]; n != nil {
			n.Name, n.Routes = name, parseRouteAds(raw)
		}
	}
	rows.Close()
	records, err := s.db.Query("SELECT node_id,name,lan_ip FROM dns_records ORDER BY name")
	if err != nil {
		return
	}
	defer records.Close()
	for records.Next() {
		var id string
		var record dnsRecord
		if records.Scan(&id, &record.Name, &record.IP) != nil {
			continue
		}
		if n := byID[id]; n != nil {
			record.VirtualIP = translatedIP(record.IP, n.Routes, true)
			n.DNSRecords = append(n.DNSRecords, record)
		}
	}
}


func validDNSName(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}


type routeChange struct {
	Route string `json:"route"`
}


func mustPrefix(raw string) netip.Prefix { p, _ := netip.ParsePrefix(raw); return p }
func prefixOverlapsAny(p netip.Prefix, used []netip.Prefix) bool {
	for _, u := range used {
		if p.Overlaps(u) {
			return true
		}
	}
	return false
}
func allocateVirtual(bits int, used []netip.Prefix) string {
	pool, _ := netip.ParsePrefix("10.77.0.0/16")
	step := uint32(1) << uint(32-bits)
	base := binary.BigEndian.Uint32(pool.Addr().AsSlice())
	for value := base; value+step-1 <= base+65535; value += step {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		p := netip.PrefixFrom(netip.AddrFrom4(raw), bits)
		if !prefixOverlapsAny(p, used) {
			return p.String()
		}
	}
	return ""
}

func metricKey(from, to string) string { return from + "\x00" + to }

// telemetry records link health reported by registered nodes.

// updateLinkMetrics folds link observations into the shared metrics table and
// reports whether the cached topology graph must be invalidated. Only real
// up/down transitions or first sightings change link costs; pure RTT reports
// arrive every few seconds and must not thrash the shared link cache.

// Admin push channel (server-sent events). Browsers open GET /v1/admin/stream
// and receive a coalesced "update" event whenever topology, configuration,
// updates or the audit trail change, so the UI reacts immediately instead of
// waiting for the next poll. The 10-second polling cycle stays in place as a
// fallback; SSE only removes the visibility lag. EventSource cannot send the
// X-Mesh-Token header, so the stream authenticates with the account session
// cookie; token-only sessions simply keep polling.
// Broadcasts are coalesced: heartbeats from many nodes within one second
// produce a single event per browser.


// Cost-model references for measured links. RTT doubles the base cost at
// rttCostReferenceMS; the caps keep one pathological measurement (a stalled
// probe, a nearly dead link) from pushing an edge out of the graph entirely,
// keeping it comparable to the down-state penalty instead.
const (
	rttCostReferenceMS = 100.0
	maxRTTCostFactor   = 6.0
	maxLossCostFactor  = 5.0
	lanCostFactor      = 0.5
	// A sustained loss shift that crosses a band boundary changes ranking;
	// jitter inside a band must not rebuild the topology.
	lossCostStep = 0.15
)


func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}


// Five failed invite attempts per IP per 30 seconds keeps a short human
// friendly code practical without making it a brute-force credential.


// accountInvite manages high-entropy invitations for human accounts. The
// short setup keys above remain dedicated to enrolling mesh nodes.


// adminGraph validates and saves manually managed mesh links.


func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
func intSqrtCeil(n int) int {
	if n <= 1 {
		return n
	}
	r := 1
	for r*r < n {
		r++
	}
	return r
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// registeredNode combines the three per-heartbeat lookups (node, owner and
// role override) into one indexed query.

// register authenticates a node, assigns its mesh address, and renews its lease.

// registrationChangesTopology deliberately ignores LastSeen: a normal
// heartbeat only renews the lease and must not trigger a network-wide
// bootstrap broadcast. A node returning from offline is a topology change
// because it becomes eligible for links again.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sanitizeLanAddrs keeps only well-formed IPv4 "ip:port" entries (max 8) from
// a node's reported LAN address list. Invalid entries are dropped instead of
// rejecting the whole registration: a node must never fail its heartbeat
// because of an odd interface configuration.
func sanitizeLanAddrs(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, raw := range addrs {
		host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			continue
		}
		out = append(out, net.JoinHostPort(ip.String(), port))
		if len(out) >= 8 {
			break
		}
	}
	return out
}

// rendezvousRegister coordinates peer discovery for NAT traversal.

// rendezvousWait holds a request until the matching peer is ready.
func topologyVersion(nodes []node) string {
	var a []string
	for _, n := range nodes {
		a = append(a, strings.Join([]string{n.ID, n.PublicKey, n.NAT, n.Role, n.Endpoint, n.MeshIP, strconv.Itoa(n.Capacity)}, ":"))
	}
	h := sha256.Sum256([]byte(strings.Join(a, "|")))
	return hex.EncodeToString(h[:])[:16]
}

// bootstrapTopologyVersion fingerprints everything that can change a node's
// forwarding view. topologyVersion is intentionally kept as the link-cache
// key, while this version also covers enriched network metadata and the
// effective edges. Otherwise a pushed manual/config/route change can carry
// the old version and be silently discarded by clients.
func bootstrapTopologyVersion(nodes []node, links []link) string {
	// Lease refreshes and uptime do not change the forwarding view. Hash a
	// copy so live status fields remain available in full/admin responses.
	nodes = append([]node(nil), nodes...)
	// Cache hits may represent an empty edge list as nil rather than [].
	links = append([]link(nil), links...)
	for i := range nodes {
		nodes[i].LastSeen = 0
		nodes[i].UptimeSeconds = 0
	}
	b, _ := json.Marshal(struct {
		Nodes []node `json:"nodes"`
		Links []link `json:"links"`
	}{nodes, links})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:16]
}
func weightedPeerOrder(client node, peers []node) []node {
	rank := append([]node(nil), peers...)
	sort.Slice(rank, func(i, j int) bool {
		// Weighted rendezvous hashing gives every client a stable preference
		// order. Capacity raises a relay's chance without globally reshuffling
		// assignments when an unrelated node appears or disappears.
		si := rendezvousScore(client.ID, rank[i].ID, rank[i].Capacity)
		sj := rendezvousScore(client.ID, rank[j].ID, rank[j].Capacity)
		if si != sj {
			return si < sj
		}
		return rank[i].ID < rank[j].ID
	})
	return rank
}
func rendezvousScore(clientID, peerID string, capacity int) uint64 {
	if capacity < 1 {
		capacity = 1
	}
	h := sha256.Sum256([]byte(clientID + ":" + peerID))
	// A lower weighted score wins. Do not use endpoint data: it changes after
	// NAT rebinding and would needlessly restart symmetric-NAT connections.
	return binary.BigEndian.Uint64(h[:8]) / uint64(capacity)
}

// links builds the forwarding graph from policy and observed link metrics.
//
// Invariants, in priority order:
//  1. Reachability: the effective graph over all online nodes is always
//     connected. Manual islands, blocked edges, and superpeers going offline
//     are healed by bridging components instead of stranding clients.
//  2. Minimal churn: weighted rendezvous hashing keeps client assignments
//     stable when unrelated nodes join or leave, and the backbone ring only
//     rewires the edges adjacent to the position that changed.
//  3. Redundancy: the backbone keeps at least ring degree (2), so the mesh
//     survives the loss of any single superpeer without a partition.

// backboneLinks wires the superpeer backbone as a ring over sorted node IDs
// plus redundant chords. The ring alone guarantees connectivity and only
// changes the two edges adjacent to a position when one superpeer joins or
// leaves; chords shorten paths and add redundancy but are never required for
// reachability. Degree is floored at 2: honoring degree 1 produced a perfect
// matching (or, with an odd peer count, no backbone at all), silently
// partitioning the mesh after the first superpeer failure.

// ensureConnected is the safety net that keeps the mesh reachable: after all
// other graph rules (manual edits, blocked pairs, departed nodes) have been
// applied, any remaining disconnected components are bridged with the
// cheapest deterministic edges. Repairs are idempotent and independent of
// live telemetry, so repeated builds produce the same bridges. Explicitly
// blocked pairs are never restored: if admin policy blocks every candidate
// pair between two components, those components stay disconnected.

// bridgeNodes picks the pair of nodes joining two components. Superpeers are
// preferred on both ends (client degree stays low), then weighted rendezvous
// hashing breaks ties so the same components always yield the same bridge,
// biased toward higher-capacity relays. Blocked pairs are skipped; ok is
// false when every possible pair is blocked.

// superpeerNodes returns the online superpeers in directory order. Nodes are
// loaded ORDER BY node_id, so the backbone ring is deterministic.

// blockedEdgeSet collects blocked pairs among the online nodes once per graph
// build instead of once per filtering pass.


// cachedTopologyLinks shares the graph calculation across all bootstrap
// responses in one topology push. The directory remains freshly loaded per
// request, so endpoint and lease data are never served from this cache.


func edgeKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + ":" + b
}

// addAutomaticClientLinks preserves managed backbone edges while attaching
// every client to its preferred peers in weighted rendezvous order: normally
// the superpeers, or the whole directory when no superpeer is online. Blocked
// pairs are skipped outright so they never consume a client's link budget,
// and the wanted count is floored at one so a blocked first choice or a
// misconfiguration still leaves the client reachable.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// bootstrap returns the topology and connection details a node needs to join.

// adminRevoked lists banned node identities shown in the access page.
