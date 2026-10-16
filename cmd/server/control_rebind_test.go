package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"home-udp-mesh/internal/protocol"
)

func dialControlWS(t *testing.T, srvURL, token string) *websocket.Conn {
	t.Helper()
	u, err := url.Parse("ws" + strings.TrimPrefix(srvURL, "http") + "/v1/ws")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := websocket.NewConfig(u.String(), "http://"+u.Host)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Header.Set("X-Mesh-Token", token)
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// TestControlReconnectRebindsNodeExclusively reproduces the desync where a
// reconnecting node kept its stale control binding: the coordinator then held
// two connections for one node ID and event delivery picked between them at
// random, so pushes and symmetric-scan requests landed on the dead socket.
func TestControlReconnectRebindsNodeExclusively(t *testing.T) {
	s := testAuthServer(t)
	s.inviteAttempts = map[string][]time.Time{}
	s.controls = map[*controlClient]string{}
	handler := websocket.Server{
		Handler:   websocket.Handler(s.controlWS),
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
		"role": "client", "endpoint": "127.0.0.1:23001", "capacity": 1,
	})
	register := func() controlFrame {
		return controlFrame{Method: http.MethodPost, Path: "/v1/register", Body: body}
	}

	first := dialControlWS(t, srv.URL, s.token)
	defer first.Close()
	var out controlFrame
	if err := websocket.JSON.Send(first, register()); err != nil {
		t.Fatal(err)
	}
	if err := websocket.JSON.Receive(first, &out); err != nil || out.Status != http.StatusOK {
		t.Fatalf("first registration failed: %v %+v", err, out)
	}

	second := dialControlWS(t, srv.URL, s.token)
	defer second.Close()
	if err := websocket.JSON.Send(second, register()); err != nil {
		t.Fatal(err)
	}
	if err := websocket.JSON.Receive(second, &out); err != nil || out.Status != http.StatusOK {
		t.Fatalf("re-registration failed: %v %+v", err, out)
	}

	s.controlMu.Lock()
	candidates := 0
	for _, id := range s.controls {
		if id == identity.ID {
			candidates++
		}
	}
	s.controlMu.Unlock()
	if candidates != 1 {
		t.Fatalf("node bound to %d control connections after reconnect, want 1", candidates)
	}

	if !s.sendControlEvent(identity.ID, controlFrame{Event: "topology"}) {
		t.Fatal("sendControlEvent could not deliver to the reconnected node")
	}
	// The register already triggered one pushed topology; any received
	// topology event proves delivery reaches the live connection.
	if err := websocket.JSON.Receive(second, &out); err != nil || out.Event != "topology" {
		t.Fatalf("topology event not delivered to the live connection: %v %+v", err, out)
	}

	// The stale connection must have been closed by the coordinator. It may
	// still hold buffered frames (the topology push from the first
	// registration), so drain until the read fails.
	_ = first.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ignored controlFrame
	for i := 0; i < 16; i++ {
		if err := websocket.JSON.Receive(first, &ignored); err != nil {
			break // closed by the coordinator as expected
		}
		if i == 15 {
			t.Fatal("stale control connection stayed readable")
		}
	}
}
