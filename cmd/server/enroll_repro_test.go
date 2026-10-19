package main

// These tests cover enroll repro behavior and regression cases.
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

// fullWSHandler mimics the real mux wiring including the invite-consuming handshake.
func fullWSHandler(s *server) websocket.Server {
	return websocket.Server{
		Handler: websocket.Handler(s.controlWS),
		Handshake: func(_ *websocket.Config, r *http.Request) error {
			if !s.networkTokenValid(r) {
				if !s.allowInviteAttempt(r.RemoteAddr) || !s.consumeInvite(r.Header.Get("X-Mesh-Invite")) {
					return http.ErrAbortHandler
				}
			}
			return nil
		},
	}
}

func createInvite(t *testing.T, s *server) string {
	t.Helper()
	admin := authRequest(http.MethodPost, "/v1/admin/invites", nil)
	admin.Header.Set("X-Mesh-Token", s.token)
	w := httptest.NewRecorder()
	s.adminInvite(w, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("invite creation status = %d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		InviteToken string `json:"invite_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.InviteToken == "" {
		t.Fatal("no invite token returned")
	}
	return out.InviteToken
}

// enroll mimics the mesh-node client: connect with ONLY the invite header,
// then push a register frame through the control websocket.
func enroll(t *testing.T, srvURL, invite string) controlFrame {
	t.Helper()
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
		"role": "auto", "endpoint": "127.0.0.1:23001", "capacity": 1,
	})
	u, _ := url.Parse("ws" + strings.TrimPrefix(srvURL, "http") + "/v1/ws")
	cfg, _ := websocket.NewConfig(u.String(), "http://"+u.Host)
	cfg.Header.Set("X-Mesh-Invite", invite)
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatalf("handshake with invite failed: %v", err)
	}
	defer ws.Close()
	if err := websocket.JSON.Send(ws, controlFrame{Method: http.MethodPost, Path: "/v1/register", Body: body}); err != nil {
		t.Fatal(err)
	}
	var out controlFrame
	if err := websocket.JSON.Receive(ws, &out); err != nil {
		t.Fatalf("register reply: %v", err)
	}
	return out
}

func TestReproEnrollWithGlobalToken(t *testing.T) {
	s := testAuthServer(t)
	s.inviteAttempts = map[string][]time.Time{}
	s.controls = map[*controlClient]string{}
	srv := httptest.NewServer(fullWSHandler(s))
	defer srv.Close()
	out := enroll(t, srv.URL, createInvite(t, s))
	if out.Status != http.StatusOK {
		t.Fatalf("enroll with global token: status=%d body=%s", out.Status, out.Error)
	}
}

func TestReproEnrollWithoutGlobalToken(t *testing.T) {
	s := testAuthServer(t)
	s.token = "" // deployment without MESH_NETWORK_TOKEN
	s.inviteAttempts = map[string][]time.Time{}
	s.controls = map[*controlClient]string{}
	srv := httptest.NewServer(fullWSHandler(s))
	defer srv.Close()
	now := time.Now().Unix()
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at) VALUES('ABC234',?,?)", now, now+60); err != nil {
		t.Fatal(err)
	}
	out := enroll(t, srv.URL, "ABC234")
	if out.Status != http.StatusOK {
		t.Fatalf("enroll without global token: status=%d body=%s", out.Status, out.Error)
	}
}
