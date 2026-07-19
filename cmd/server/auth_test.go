package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"home-udp-mesh/internal/protocol"
)

func testAuthServer(t *testing.T) *server {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err = db.Exec("PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL"); err != nil {
		t.Fatal(err)
	}
	s := &server{
		db: db, token: "test-network-token-that-is-long-enough",
		ttl: 45, backboneDegree: 6, clientLinks: 2, symmetricLinks: 3,
		accountAttempts: map[string][]time.Time{},
	}
	_, s.network, _ = net.ParseCIDR("10.77.0.0/24")
	if err = s.init(); err != nil {
		t.Fatal(err)
	}
	return s
}

func authRequest(method, target string, body any) *http.Request {
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		encoded, _ := json.Marshal(body)
		reader = strings.NewReader(string(encoded))
	}
	r := httptest.NewRequest(method, target, reader)
	r.RemoteAddr = "127.0.0.1:40123"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func TestAccountRegistrationLoginAndInvites(t *testing.T) {
	s := testAuthServer(t)
	t.Setenv("MESH_ACCOUNT_BOOTSTRAP_TOKEN", s.token)
	password := "correct horse battery staple"

	first := authRequest(http.MethodPost, "/v1/auth/register", map[string]string{
		"username":     "alice",
		"password":     password,
		"invite_token": s.token,
	})
	firstResponse := httptest.NewRecorder()
	s.accountRegister(firstResponse, first)
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("first registration status = %d, body=%s", firstResponse.Code, firstResponse.Body.String())
	}
	var firstAccount struct {
		Token string `json:"network_token"`
	}
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &firstAccount); err != nil || firstAccount.Token == "" {
		t.Fatalf("first account did not receive a network token: %s", firstResponse.Body.String())
	}
	var stored string
	if err := s.db.QueryRow("SELECT password_hash FROM users WHERE username='alice'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == password || bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) != nil {
		t.Fatal("password was not stored as a usable one-way hash")
	}

	noInvite := authRequest(http.MethodPost, "/v1/auth/register", map[string]string{
		"username": "bob", "password": password,
	})
	noInviteResponse := httptest.NewRecorder()
	s.accountRegister(noInviteResponse, noInvite)
	if noInviteResponse.Code != http.StatusForbidden {
		t.Fatalf("registration without invite status = %d, want %d", noInviteResponse.Code, http.StatusForbidden)
	}

	wrongLogin := authRequest(http.MethodPost, "/v1/auth/login", map[string]string{
		"username": "alice", "password": "wrong password",
	})
	wrongResponse := httptest.NewRecorder()
	s.accountLogin(wrongResponse, wrongLogin)
	if wrongResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want %d", wrongResponse.Code, http.StatusUnauthorized)
	}

	login := authRequest(http.MethodPost, "/v1/auth/login", map[string]string{
		"username": "alice", "password": password,
	})
	loginResponse := httptest.NewRecorder()
	s.accountLogin(loginResponse, login)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 2 || cookies[0].HttpOnly != true {
		t.Fatalf("login did not issue secure session/CSRF cookie pair: %#v", cookies)
	}
	var session, csrf *http.Cookie
	for _, cookie := range cookies {
		switch cookie.Name {
		case sessionCookieName:
			session = cookie
		case csrfCookieName:
			csrf = cookie
		}
	}
	if session == nil || csrf == nil || session.Value == csrf.Value {
		t.Fatal("session and CSRF cookies were not issued")
	}

	protected := authRequest(http.MethodGet, "/v1/admin/audit", nil)
	protected.AddCookie(session)
	protectedResponse := httptest.NewRecorder()
	s.adminAudit(protectedResponse, protected)
	if protectedResponse.Code != http.StatusOK {
		t.Fatalf("session did not authorize admin read: %d", protectedResponse.Code)
	}
	forbiddenMutation := authRequest(http.MethodPost, "/v1/admin/account-invites", map[string]any{})
	forbiddenMutation.AddCookie(session)
	forbiddenResponse := httptest.NewRecorder()
	s.accountInvite(forbiddenResponse, forbiddenMutation)
	if forbiddenResponse.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token status = %d, want %d", forbiddenResponse.Code, http.StatusForbidden)
	}

	inviteRequest := authRequest(http.MethodPost, "/v1/admin/account-invites", map[string]any{})
	inviteRequest.AddCookie(session)
	inviteRequest.AddCookie(csrf)
	inviteRequest.Header.Set("X-CSRF-Token", csrf.Value)
	inviteResponse := httptest.NewRecorder()
	s.accountInvite(inviteResponse, inviteRequest)
	if inviteResponse.Code != http.StatusCreated {
		t.Fatalf("account invite status = %d, body=%s", inviteResponse.Code, inviteResponse.Body.String())
	}
	var invite struct {
		Token string `json:"invite_token"`
	}
	if err := json.Unmarshal(inviteResponse.Body.Bytes(), &invite); err != nil || invite.Token == "" {
		t.Fatalf("missing account invite token: %s", inviteResponse.Body.String())
	}

	second := authRequest(http.MethodPost, "/v1/auth/register", map[string]string{
		"username": "bob", "password": password, "invite_token": invite.Token,
	})
	secondResponse := httptest.NewRecorder()
	s.accountRegister(secondResponse, second)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("invited registration status = %d, body=%s", secondResponse.Code, secondResponse.Body.String())
	}
	var secondAccount struct {
		Token string `json:"network_token"`
	}
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &secondAccount); err != nil || secondAccount.Token == "" {
		t.Fatalf("second account did not receive a network token: %s", secondResponse.Body.String())
	}
	reused := authRequest(http.MethodPost, "/v1/auth/register", map[string]string{
		"username": "carol", "password": password, "invite_token": invite.Token,
	})
	reusedResponse := httptest.NewRecorder()
	s.accountRegister(reusedResponse, reused)
	if reusedResponse.Code != http.StatusForbidden {
		t.Fatalf("reused invite status = %d, want %d", reusedResponse.Code, http.StatusForbidden)
	}

	var aliceID, bobID int64
	if err := s.db.QueryRow("SELECT id FROM users WHERE username='alice'").Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT id FROM users WHERE username='bob'").Scan(&bobID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for _, n := range []struct {
		id, endpoint, mesh string
		owner              int64
	}{{"alice-device", "127.0.0.1:12001", "10.77.0.10", aliceID}, {"bob-device", "127.0.0.1:12002", "10.77.0.11", bobID}} {
		if _, err := s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, n.id, "public-"+n.id, "cone", "client", n.endpoint, "auto", 1, 1, now, now, n.mesh, n.owner); err != nil {
			t.Fatal(err)
		}
	}
	aliceTopology := authRequest(http.MethodGet, "/v1/admin/topology?scope=all", nil)
	aliceTopology.Header.Set("X-Mesh-Token", firstAccount.Token)
	aliceTopologyResponse := httptest.NewRecorder()
	s.adminTopology(aliceTopologyResponse, aliceTopology)
	if aliceTopologyResponse.Code != http.StatusOK || !strings.Contains(aliceTopologyResponse.Body.String(), "alice-device") || strings.Contains(aliceTopologyResponse.Body.String(), "bob-device") {
		t.Fatalf("alice topology was not isolated: status=%d body=%s", aliceTopologyResponse.Code, aliceTopologyResponse.Body.String())
	}
	bobService := authRequest(http.MethodPost, "/v1/services", map[string]any{"node_id": "bob-device", "name": "private", "target_host": "127.0.0.1", "target_port": 8080})
	bobService.Header.Set("X-Mesh-Token", firstAccount.Token)
	bobServiceResponse := httptest.NewRecorder()
	s.service(bobServiceResponse, bobService)
	if bobServiceResponse.Code != http.StatusNotFound {
		t.Fatalf("alice token accessed bob device service: %d", bobServiceResponse.Code)
	}

	identity, err := protocol.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registrationBody := map[string]any{"node_id": identity.ID, "public_key": identity.Public, "nat_type": "cone", "role": "auto", "endpoint": "127.0.0.1:12003", "capacity": 1}
	registerAlice := authRequest(http.MethodPost, "/v1/register", registrationBody)
	registerAlice.Header.Set("X-Mesh-Token", firstAccount.Token)
	registerAliceResponse := httptest.NewRecorder()
	s.register(registerAliceResponse, registerAlice)
	if registerAliceResponse.Code != http.StatusOK {
		t.Fatalf("alice device registration status = %d, body=%s", registerAliceResponse.Code, registerAliceResponse.Body.String())
	}
	registerBob := authRequest(http.MethodPost, "/v1/register", registrationBody)
	registerBob.Header.Set("X-Mesh-Token", secondAccount.Token)
	registerBobResponse := httptest.NewRecorder()
	s.register(registerBobResponse, registerBob)
	if registerBobResponse.Code != http.StatusForbidden {
		t.Fatalf("bob claimed alice device: status=%d body=%s", registerBobResponse.Code, registerBobResponse.Body.String())
	}

	// A browser account session must not become a mesh-node credential.
	spoofNode := authRequest(http.MethodPost, "/v1/register", map[string]string{})
	spoofNode.AddCookie(session)
	spoofResponse := httptest.NewRecorder()
	s.register(spoofResponse, spoofNode)
	if spoofResponse.Code != http.StatusUnauthorized {
		t.Fatalf("account session authorized node registration: %d", spoofResponse.Code)
	}
}
