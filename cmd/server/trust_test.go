package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"home-udp-mesh/internal/protocol"
)

// enrollHTTP registers a node through the legacy HTTP path with a one-time
// invite and returns its identity plus the issued credential.
func enrollHTTP(t *testing.T, s *server, invite string) (identity *protocol.Identity, token string) {
	t.Helper()
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := authRequest(http.MethodPost, "/v1/register", registerBody(identity))
	r.Header.Set("X-Mesh-Invite", invite)
	w := httptest.NewRecorder()
	s.register(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("register status = %d, body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Token string `json:"network_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("register reply is not JSON: %v", err)
	}
	return identity, out.Token
}

func registerBody(identity *protocol.Identity) map[string]any {
	return map[string]any{
		"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone",
		"role": "auto", "endpoint": "127.0.0.1:23001", "capacity": 1,
	}
}

// newInviteWithOwner inserts a one-time invite in the state a WebSocket
// enrollment leaves behind (consumed within the follow-up window), mirroring
// what the admin panel creates from an authenticated session.
func newInviteWithOwner(t *testing.T, s *server, code string) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at,used_at) VALUES(?,?,?,?)", code, now, now+600, now); err != nil {
		t.Fatal(err)
	}
}

func nodeTokenRequest(s *server, method, target, token string, body any) (*http.Request, *httptest.ResponseRecorder) {
	r := authRequest(method, target, body)
	if token != "" {
		r.Header.Set("X-Mesh-Token", token)
	}
	return r, httptest.NewRecorder()
}

func TestInviteEnrollmentIssuesScopedNodeToken(t *testing.T) {
	s := testAuthServer(t)
	s.inviteAttempts = map[string][]time.Time{}
	newInviteWithOwner(t, s, "AB12CD")

	id, token := enrollHTTP(t, s, "AB12CD")
	if token == "" {
		t.Fatal("invite enrollment did not return a network_token")
	}

	// The credential authenticates node-facing endpoints.
	r, w := nodeTokenRequest(s, http.MethodGet, "/v1/bootstrap/"+id, token, nil)
	r.SetPathValue("node_id", id)
	s.bootstrap(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap with node token status = %d, body=%s", w.Code, w.Body.String())
	}

	// But it is not an account token and must not open the admin API.
	if _, ok := s.accountTokenUser(r); ok {
		t.Fatal("node token resolved to an account token user")
	}
	if !s.anyNodeTokenValid(r) {
		t.Fatal("issued credential not recognized as node token")
	}
	aw, ar := nodeTokenRequest(s, http.MethodGet, "/v1/admin/revoked", token, nil)
	if s.adminAuth(aw, ar) {
		t.Fatal("node token satisfied adminAuth")
	}
}

func TestRemovedNodeStaysRemoved(t *testing.T) {
	s := testAuthServer(t)
	s.inviteAttempts = map[string][]time.Time{}
	newInviteWithOwner(t, s, "XY234Z")

	identity, token := enrollHTTP(t, s, "XY234Z")

	// Remove the node the way the admin panel does.
	r, w := nodeTokenRequest(s, http.MethodDelete, "/v1/admin/nodes/"+identity.ID, s.token, nil)
	s.adminNode(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin delete status = %d, body=%s", w.Code, w.Body.String())
	}
	if !s.nodeRevoked(identity.ID) {
		t.Fatal("removed node is not banned")
	}

	// The per-node credential died with the node row.
	ar, _ := nodeTokenRequest(s, http.MethodGet, "/v1/bootstrap/"+identity.ID, token, nil)
	if s.anyNodeTokenValid(ar) {
		t.Fatal("node token still valid after removal")
	}

	// A restart re-registers with the same identity; the ban must hold.
	newInviteWithOwner(t, s, "CD45EF")
	rr := authRequest(http.MethodPost, "/v1/register", registerBody(identity))
	rr.Header.Set("X-Mesh-Invite", "CD45EF")
	rw := httptest.NewRecorder()
	s.register(rw, rr)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("re-registration of removed node status = %d, want 403, body=%s", rw.Code, rw.Body.String())
	}

	// Unban allows a fresh enrollment with the same identity.
	ur, uw := nodeTokenRequest(s, http.MethodDelete, "/v1/admin/revoked/"+identity.ID, s.token, nil)
	ur.SetPathValue("node_id", identity.ID)
	s.adminUnban(uw, ur)
	if uw.Code != http.StatusOK {
		t.Fatalf("unban status = %d, body=%s", uw.Code, uw.Body.String())
	}
	if s.nodeRevoked(identity.ID) {
		t.Fatal("node still banned after unban")
	}
	newInviteWithOwner(t, s, "EF56GH")
	fr := authRequest(http.MethodPost, "/v1/register", registerBody(identity))
	fr.Header.Set("X-Mesh-Invite", "EF56GH")
	fw := httptest.NewRecorder()
	s.register(fw, fr)
	if fw.Code != http.StatusOK {
		t.Fatalf("post-unban re-enrollment status = %d, body=%s", fw.Code, fw.Body.String())
	}
}

func TestLegacyNetworkTokenRegistrationUnchanged(t *testing.T) {
	s := testAuthServer(t)
	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := authRequest(http.MethodPost, "/v1/register", registerBody(identity))
	r.Header.Set("X-Mesh-Token", s.token)
	w := httptest.NewRecorder()
	s.register(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy register status = %d, body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if tok, ok := out["network_token"]; ok && tok != "" {
		t.Fatalf("legacy registration unexpectedly received a token: %v", tok)
	}
	rr := authRequest(http.MethodGet, "/v1/bootstrap/"+identity.ID, nil)
	rr.Header.Set("X-Mesh-Token", s.token)
	rr.SetPathValue("node_id", identity.ID)
	bw := httptest.NewRecorder()
	s.bootstrap(bw, rr)
	if bw.Code != http.StatusOK {
		t.Fatalf("legacy bootstrap status = %d, body=%s", bw.Code, bw.Body.String())
	}
}
