package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// controlWS handles the long-lived control connection used for node updates.
func (s *server) controlWS(ws *websocket.Conn) {
	credential := ws.Request().Header.Get("X-Mesh-Token")
	if credential == "" {
		credential = s.token
	}
	client := &controlClient{c: ws, session: s.controlSessions.Add(1), invited: ws.Request().Header.Get("X-Mesh-Invite") != "", invite: ws.Request().Header.Get("X-Mesh-Invite"), credential: credential}
	// Control frames are small JSON documents. The library default of 32 MiB
	// per frame lets one authenticated client exhaust memory with a single
	// oversized frame.
	ws.MaxPayloadBytes = controlMaxFrameBytes
	defer func() {
		s.controlMu.Lock()
		delete(s.controls, client)
		s.controlMu.Unlock()
		ws.Close()
	}()
	for {
		// Nodes push a heartbeat through this connection at least every
		// heartbeat interval. A silent connection is dead (lost NAT, powered
		// off host without a TCP reset): close it so its goroutine and control
		// slot are released instead of lingering until the next failed push.
		_ = ws.SetReadDeadline(time.Now().Add(controlIdleReadTimeout))
		var in controlFrame
		if err := websocket.JSON.Receive(ws, &in); err != nil {
			return
		}
		credential, invite, invited := client.authState()
		var out controlFrame
		switch {
		case in.Method == http.MethodPost && in.Path == "/v1/symmetric-scan":
			out = s.symmetricScanRequest(client, in)
		case in.Method == http.MethodPost && in.Path == "/v1/symmetric-scan/ack":
			out = s.symmetricScanACK(client, in)
		default:
			out = s.controlRequestWithAuth(in, credential, invite)
		}
		if invited && in.Method == http.MethodPost && in.Path == "/v1/register" && out.Status >= 200 && out.Status < 300 {
			var body map[string]any
			_ = json.Unmarshal(out.Body, &body)
			if _, exists := body["network_token"]; !exists && s.token != "" {
				body["network_token"] = s.token
			}
			if token, ok := body["network_token"].(string); ok && token != "" {
				client.finishInvite(token)
			}
			out.Body, _ = json.Marshal(body)
			client.finishInvite("")
		}
		if err := client.send(out); err != nil {
			return
		}
		if in.Method == http.MethodPost && in.Path == "/v1/register" && out.Status >= 200 && out.Status < 300 {
			var registration struct {
				ID string `json:"node_id"`
			}
			if json.Unmarshal(in.Body, &registration) == nil && registration.ID != "" {
				s.controlMu.Lock()
				// A reconnecting node's previous, half-open connection can keep
				// the node ID bound until its reader notices. Rebind
				// exclusively: otherwise the node has two bindings and event
				// delivery picks one at random, so topology pushes and
				// symmetric-scan requests can silently land on the dead one.
				superseded := false
				for other := range s.controls {
					if other != client && s.controls[other] == registration.ID {
						// Register post-processing is not synchronized, so a
						// slow old registration can reach this loop after the
						// node already reconnected on a newer socket. Closing
						// by "not me" alone would then kill the fresh
						// connection. Supersession is decided by accept
						// order: the newest session owns the binding.
						if other.session > client.session {
							superseded = true
							continue
						}
						delete(s.controls, other)
						stale := other
						go func() { _ = stale.c.Close() }()
					}
				}
				alreadySynced := s.controls[client] == registration.ID
				if !superseded {
					s.controls[client] = registration.ID
				}
				s.controlMu.Unlock()
				var result struct {
					TopologyChanged bool `json:"topology_changed"`
				}
				_ = json.Unmarshal(out.Body, &result)
				// Register is also the heartbeat. Pushing after every heartbeat made
				// every node bootstrap for every other node (O(n²) database reads and
				// link calculations). Only broadcast when the registration changed
				// data that can affect the topology.
				if result.TopologyChanged {
					s.pushTopologies()
				} else if !alreadySynced {
					// A reconnecting node may have missed broadcasts while its
					// websocket was down. Catch it up without a full fan-out.
					s.pushTopology(client, registration.ID)
				}
			}
		}
	}
}

func (s *server) registeredControlID(client *controlClient) string {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	return s.controls[client]
}

func (s *server) sendControlEvent(nodeID string, frame controlFrame) bool {
	s.controlMu.Lock()
	targets := make([]*controlClient, 0, 2)
	for client, id := range s.controls {
		if id == nodeID {
			targets = append(targets, client)
		}
	}
	s.controlMu.Unlock()
	if len(targets) == 0 {
		return false
	}
	// The register rebind normally leaves a single live candidate. Trying
	// every candidate keeps delivery working while a half-open connection has
	// not been reaped yet; map iteration order would otherwise flip a coin
	// between the live and the dead socket.
	for _, target := range targets {
		if err := target.send(frame); err != nil {
			_ = target.c.Close()
			continue
		}
		return true
	}
	return false
}

func validSymmetricSessionID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16
}

func (s *server) symmetricScanRequest(client *controlClient, in controlFrame) controlFrame {
	sourceID := s.registeredControlID(client)
	if sourceID == "" {
		return controlFrame{Status: http.StatusConflict, Error: "control connection is not registered"}
	}
	var request struct {
		TargetID  string `json:"target_node_id"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(in.Body, &request); err != nil || request.TargetID == "" || !validSymmetricSessionID(request.SessionID) {
		return controlFrame{Status: http.StatusBadRequest, Error: "invalid symmetric scan request"}
	}
	var sourceNAT, sourceEndpoint, targetNAT, targetRole string
	if err := s.db.QueryRow("SELECT nat_type,endpoint FROM nodes WHERE node_id=?", sourceID).Scan(&sourceNAT, &sourceEndpoint); err != nil {
		return controlFrame{Status: http.StatusNotFound, Error: "source node not found"}
	}
	if err := s.db.QueryRow("SELECT nat_type,role FROM nodes WHERE node_id=?", request.TargetID).Scan(&targetNAT, &targetRole); err != nil {
		return controlFrame{Status: http.StatusNotFound, Error: "target node not found"}
	}
	if sourceNAT != "symmetric" || targetNAT != "cone" || targetRole != "superpeer" || sourceEndpoint == "" {
		return controlFrame{Status: http.StatusConflict, Error: "nodes are not a symmetric-to-superpeer pair"}
	}

	now := time.Now()
	s.symmetricMu.Lock()
	for id, pending := range s.symmetricRendezvous {
		if now.After(pending.expires) {
			delete(s.symmetricRendezvous, id)
		}
	}
	s.symmetricRendezvous[request.SessionID] = symmetricRendezvous{source: sourceID, target: request.TargetID, expires: now.Add(30 * time.Second)}
	s.symmetricMu.Unlock()
	body, _ := json.Marshal(map[string]string{
		"peer_node_id": sourceID,
		"session_id":   request.SessionID,
		"endpoint":     sourceEndpoint,
	})
	if !s.sendControlEvent(request.TargetID, controlFrame{Event: "symmetric_scan", Body: body}) {
		s.symmetricMu.Lock()
		delete(s.symmetricRendezvous, request.SessionID)
		s.symmetricMu.Unlock()
		return controlFrame{Status: http.StatusServiceUnavailable, Error: "target node is not connected"}
	}
	response, _ := json.Marshal(map[string]bool{"delivered": true})
	return controlFrame{Status: http.StatusAccepted, Body: response}
}

func (s *server) symmetricScanACK(client *controlClient, in controlFrame) controlFrame {
	targetID := s.registeredControlID(client)
	if targetID == "" {
		return controlFrame{Status: http.StatusConflict, Error: "control connection is not registered"}
	}
	var request struct {
		SourceID  string `json:"source_node_id"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(in.Body, &request); err != nil || request.SourceID == "" || !validSymmetricSessionID(request.SessionID) {
		return controlFrame{Status: http.StatusBadRequest, Error: "invalid symmetric scan ACK"}
	}
	s.symmetricMu.Lock()
	pending, exists := s.symmetricRendezvous[request.SessionID]
	if exists && pending.source == request.SourceID && pending.target == targetID && time.Now().Before(pending.expires) {
		delete(s.symmetricRendezvous, request.SessionID)
	} else {
		exists = false
	}
	s.symmetricMu.Unlock()
	if !exists {
		return controlFrame{Status: http.StatusConflict, Error: "unknown or expired symmetric scan session"}
	}
	body, _ := json.Marshal(map[string]string{"session_id": request.SessionID, "peer_node_id": targetID})
	if !s.sendControlEvent(request.SourceID, controlFrame{Event: "symmetric_scan_ack", Body: body}) {
		return controlFrame{Status: http.StatusServiceUnavailable, Error: "source node is not connected"}
	}
	response, _ := json.Marshal(map[string]bool{"acknowledged": true})
	return controlFrame{Status: http.StatusOK, Body: response}
}

func (c *controlClient) send(frame controlFrame) error {
	c.ws.Lock()
	defer c.ws.Unlock()
	_ = c.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := websocket.JSON.Send(c.c, frame)
	_ = c.c.SetWriteDeadline(time.Time{})
	return err
}

// pushTopologies sends only to connected nodes, so a topology change becomes
// visible immediately instead of waiting for a node's periodic refresh.
// pushTopologies sends refreshed network views to connected nodes.
func (s *server) pushTopologies() {
	s.controlMu.Lock()
	clients := make(map[*controlClient]string, len(s.controls))
	for client, id := range s.controls {
		clients[client] = id
	}
	s.controlMu.Unlock()
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	for client, id := range clients {
		wg.Add(1)
		go func(client *controlClient, id string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			s.pushTopology(client, id)
		}(client, id)
	}
	wg.Wait()
}

func (s *server) pushTopology(client *controlClient, id string) {
	credential, _, _ := client.authState()
	out := s.controlRequestWithToken(controlFrame{Method: http.MethodGet, Path: "/v1/bootstrap/" + id}, credential)
	if out.Status >= 200 && out.Status < 300 {
		out.Event = "topology"
		if err := client.send(out); err != nil {
			_ = client.c.Close()
		}
	}
}

// Reuse the validated HTTP handlers so both transports have exactly the same
// authorization, validation and database semantics. The HTTP API remains for
// older nodes and operational tooling.
func (s *server) controlRequest(in controlFrame) controlFrame {
	return s.controlRequestWithAuth(in, s.token, "")
}

func (s *server) controlRequestWithToken(in controlFrame, credential string) controlFrame {
	return s.controlRequestWithAuth(in, credential, "")
}

func (s *server) controlRequestWithAuth(in controlFrame, credential, invite string) controlFrame {
	if in.Method == "" || in.Path == "" {
		return controlFrame{Status: http.StatusBadRequest, Error: "missing method or path"}
	}
	r := &http.Request{
		Method:        in.Method,
		URL:           &url.URL{Scheme: "http", Host: "control", Path: in.Path},
		RequestURI:    in.Path,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(in.Body)),
		ContentLength: int64(len(in.Body)),
		RemoteAddr:    "control",
	}
	if credential != "" {
		r.Header.Set("X-Mesh-Token", credential)
	}
	if invite != "" {
		r.Header.Set("X-Mesh-Invite", invite)
	}
	w := &controlResponseWriter{header: make(http.Header)}
	switch {
	case in.Method == http.MethodPost && in.Path == "/v1/register":
		s.register(w, r)
	case in.Method == http.MethodPost && in.Path == "/v1/services":
		s.service(w, r)
	case in.Method == http.MethodPost && in.Path == "/v1/telemetry":
		s.telemetry(w, r)
	case in.Method == http.MethodPost && in.Path == "/v1/update-status":
		s.nodeUpdateStatus(w, r)
	case in.Method == http.MethodGet && strings.HasPrefix(in.Path, "/v1/bootstrap/"):
		r.SetPathValue("node_id", strings.TrimPrefix(in.Path, "/v1/bootstrap/"))
		s.bootstrap(w, r)
	case in.Method == http.MethodGet && strings.HasPrefix(in.Path, "/v1/services/"):
		p := strings.Split(strings.TrimPrefix(in.Path, "/v1/services/"), "/")
		if len(p) != 2 {
			return controlFrame{Status: 400, Error: "invalid service path"}
		}
		r.SetPathValue("node_id", p[0])
		r.SetPathValue("name", p[1])
		s.serviceDetails(w, r)
	default:
		return controlFrame{Status: http.StatusNotFound, Error: "unknown control operation"}
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	body := json.RawMessage(append([]byte(nil), w.body.Bytes()...))
	if status < 200 || status > 299 {
		return controlFrame{Status: status, Error: strings.TrimSpace(string(body))}
	}
	return controlFrame{Status: status, Body: body}
}
