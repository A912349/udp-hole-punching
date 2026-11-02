package main

import (
	"home-udp-mesh/internal/protocol"
	"net/http"
	"sort"
	"time"
)

func (s *server) telemetry(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var report struct {
		NodeID string                     `json:"node_id"`
		Links  []protocol.LinkMeasurement `json:"links"`
	}
	if err := decodeJSON(w, r, &report); err != nil || report.NodeID == "" {
		reply(w, 400, map[string]string{"error": "invalid telemetry"})
		return
	}
	if !s.requireNodeAccess(w, r, report.NodeID) {
		return
	}
	if s.updateLinkMetrics(report.NodeID, report.Links) {
		s.metricStamp.Add(1)
		s.broadcast("topology")
	}
	reply(w, 200, map[string]string{"status": "ok"})
}
func (s *server) updateLinkMetrics(nodeID string, links []protocol.LinkMeasurement) bool {
	now := time.Now()
	stateChanged := false
	s.metricsMu.Lock()
	for _, x := range links {
		if x.PeerID == "" || x.PeerID == nodeID {
			continue
		}
		k := metricKey(nodeID, x.PeerID)
		old := s.metrics[k]
		if x.RTTMS > 0 && x.RTTMS < 60000 {
			if old.RTTMS == 0 {
				old.RTTMS = x.RTTMS
			} else {
				old.RTTMS = old.RTTMS*.7 + x.RTTMS*.3
			}
		}
		// Loss is already smoothed on the node, so fold it faster (0.5/0.5).
		// Zero reports still decay the estimate toward no-loss. Only a shift
		// across a lossCostStep band invalidates the topology cache: jitter
		// inside a band must not rebuild the graph.
		previousBand := int(old.LossRate / lossCostStep)
		if x.Loss > 0 {
			if old.LossRate == 0 {
				old.LossRate = x.Loss
			} else {
				old.LossRate = old.LossRate*.5 + x.Loss*.5
			}
		} else if old.LossRate > 0 {
			old.LossRate *= 0.5
		}
		if int(old.LossRate/lossCostStep) != previousBand {
			stateChanged = true
		}
		if old.Seen.IsZero() || old.Up != x.Up || old.ViaLAN != x.ViaLAN {
			stateChanged = true
		}
		old.Up = x.Up
		old.ViaLAN = x.ViaLAN
		old.Seen = now
		s.metrics[k] = old
	}
	s.metricsMu.Unlock()
	return stateChanged
}
func (s *server) telemetryPeerOrder(client node, peers []node) []node {
	rank := append([]node(nil), peers...)
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	sort.Slice(rank, func(i, j int) bool {
		a, b := s.metrics[metricKey(client.ID, rank[i].ID)], s.metrics[metricKey(client.ID, rank[j].ID)]
		state := func(m linkMetric) int {
			if time.Since(m.Seen) >= 45*time.Second {
				return 1 // unknown: preferable to a recently confirmed failure
			}
			if m.Up {
				return 2
			}
			return 0
		}
		if stateA, stateB := state(a), state(b); stateA != stateB {
			return stateA > stateB
		}
		si := rendezvousScore(client.ID, rank[i].ID, rank[i].Capacity)
		sj := rendezvousScore(client.ID, rank[j].ID, rank[j].Capacity)
		if si != sj {
			return si < sj
		}
		return rank[i].ID < rank[j].ID
	})
	return rank
}
