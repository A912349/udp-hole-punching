package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "modernc.org/sqlite"
)

func (s *server) adminUpdateDispatch(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	var input struct {
		NodeID string `json:"node_id"`
		All    bool   `json:"all"`
	}
	if err := decodeJSON(w, r, &input); err != nil || (!input.All && input.NodeID == "") {
		reply(w, http.StatusBadRequest, map[string]string{"error": "provide node_id or all=true"})
		return
	}
	if input.NodeID != "" && !s.requireNodeAccess(w, r, input.NodeID) {
		return
	}
	sources := s.buildUpdateSources()
	if len(sources.Binaries) == 0 && len(sources.URLs) == 0 {
		reply(w, http.StatusBadRequest, map[string]string{"error": "no download links or stored binaries configured"})
		return
	}
	targets := []string{input.NodeID}
	scope := "node=" + input.NodeID
	if input.All {
		targets = s.connectedNodeIDs()
		scope = "all"
		if accountID, scoped := s.accountIDForRequest(r); scoped {
			own := targets[:0]
			for _, id := range targets {
				if s.nodeOwnedByAccount(id, accountID) {
					own = append(own, id)
				}
			}
			targets = own
		}
		if len(targets) == 0 {
			reply(w, http.StatusConflict, map[string]string{"error": "no connected nodes in your scope"})
			return
		}
	}
	body, _ := json.Marshal(sources)
	type dispatchResult struct {
		NodeID string `json:"node_id"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail,omitempty"`
	}
	results := make([]dispatchResult, 0, len(targets))
	sent := 0
	for _, id := range targets {
		arch := s.nodeArch(id)
		if arch != "" {
			if _, hasBinary := sources.Binaries[arch]; !hasBinary {
				if u := sources.URLs[arch]; u == "" {
					results = append(results, dispatchResult{NodeID: id, Detail: "no update source for " + arch})
					continue
				}
			}
		}
		if s.sendControlEvent(id, controlFrame{Event: "update", Body: body}) {
			sent++
			detail := "update sent"
			if arch != "" {
				detail += " for " + arch
			}
			results = append(results, dispatchResult{NodeID: id, OK: true, Detail: detail})
		} else {
			results = append(results, dispatchResult{NodeID: id, Detail: "node is not connected"})
		}
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "update_dispatched", fmt.Sprintf("%s sent=%d", scope, sent))
	s.broadcast("updates", "audit")
	reply(w, http.StatusOK, map[string]any{"results": results})
}

var updateStatusValues = map[string]bool{"updating": true, "restarting": true, "done": true, "failed": true}

// nodeUpdateStatus receives the node's self-update progress report. It goes
// over the same control WebSocket as registration, so no extra port or
// authentication channel is needed.
func (s *server) nodeUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var report struct {
		NodeID string `json:"node_id"`
		GoArch string `json:"goarch"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	if err := decodeJSON(w, r, &report); err != nil || report.NodeID == "" || len(report.NodeID) > 128 {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid update status report"})
		return
	}
	if !updateStatusValues[report.Status] {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid update status"})
		return
	}
	if len(report.Detail) > 512 {
		report.Detail = report.Detail[:512]
	}
	if !validGoArch(report.GoArch) {
		report.GoArch = ""
	}
	if !s.requireNodeAccess(w, r, report.NodeID) {
		return
	}
	s.updateMu.Lock()
	if s.updateResults == nil {
		s.updateResults = map[string]updateResult{}
	}
	if len(s.updateResults) >= 2048 {
		cutoff := time.Now().Add(-24 * time.Hour).Unix()
		for id, res := range s.updateResults {
			if res.At < cutoff {
				delete(s.updateResults, id)
			}
		}
	}
	s.updateResults[report.NodeID] = updateResult{Status: report.Status, Detail: report.Detail, GoArch: report.GoArch, At: time.Now().Unix()}
	s.updateMu.Unlock()
	reply(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) updateStatusSnapshot() map[string]updateResult {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	out := make(map[string]updateResult, len(s.updateResults))
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	for id, res := range s.updateResults {
		if res.At < cutoff {
			delete(s.updateResults, id)
			continue
		}
		out[id] = res
	}
	return out
}

// rebalanceRoles makes an auto-superpeer setting take effect immediately for
// already registered nodes, not only when their next heartbeat arrives.
// rebalanceRoles reports whether any role actually changed, so background
// maintenance can push fresh topologies only when the graph really moved.
