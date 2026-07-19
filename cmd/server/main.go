// Command server is the HTTP control plane. It intentionally never forwards user traffic.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/websocket"
	"home-udp-mesh/internal/protocol"
	_ "modernc.org/sqlite"
)

type node struct {
	ID            string               `json:"node_id"`
	PublicKey     string               `json:"public_key"`
	NAT           string               `json:"nat_type"`
	Role          string               `json:"role"`
	Endpoint      string               `json:"endpoint"`
	Capacity      int                  `json:"capacity"`
	MeshIP        string               `json:"mesh_ip"`
	RequestedRole string               `json:"requested_role"`
	Relay         bool                 `json:"relay_capable"`
	LastSeen      int64                `json:"last_seen"`
	CreatedAt     int64                `json:"created_at"`
	UptimeSeconds int64                `json:"uptime_seconds,omitempty"`
	Online        bool                 `json:"online"`
	Name          string               `json:"name,omitempty"`
	Routes        []routeAdvertisement `json:"routes,omitempty"`
	DNSRecords    []dnsRecord          `json:"dns_records,omitempty"`
}
type routeAdvertisement struct {
	LAN     string `json:"lan_cidr"`
	Virtual string `json:"virtual_cidr"`
}
type dnsRecord struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	VirtualIP string `json:"virtual_ip,omitempty"`
}
type link struct {
	A      string  `json:"a"`
	B      string  `json:"b"`
	Cost   float64 `json:"cost"`
	RTTMS  float64 `json:"rtt_ms,omitempty"`
	Status string  `json:"status,omitempty"`
}
type server struct {
	db                                          *sql.DB
	token                                       string
	bootstrapToken                              string
	network                                     *net.IPNet
	ttl                                         int64
	auto                                        int // 0 selects ceil(sqrt(eligible cone relays)); a positive value is an override.
	backboneDegree, clientLinks, symmetricLinks int
	configMu                                    sync.RWMutex
	inviteMu                                    sync.Mutex
	inviteAttempts                              map[string][]time.Time
	accountMu                                   sync.Mutex
	accountAttempts                             map[string][]time.Time

	sessionsMu sync.Mutex
	sessions   map[string]map[string]*rendezvousPeer
	controlMu  sync.Mutex
	controls   map[*controlClient]string
	metricsMu  sync.RWMutex
	metrics    map[string]linkMetric
}
type linkMetric struct {
	RTTMS float64
	Up    bool
	Seen  time.Time
}

type controlClient struct {
	ws         sync.Mutex
	c          *websocket.Conn
	invited    bool
	credential string
}

type rendezvousPeer struct {
	endpoint string
	natType  string
	status   string
	other    string
	otherNAT string
	ready    chan struct{}
}

func envInt(name string, fallback int) int {
	if v, e := strconv.Atoi(os.Getenv(name)); e == nil && v > 0 {
		return v
	}
	return fallback
}
func main() {
	dsn := os.Getenv("MESH_DATABASE")
	if dsn == "" {
		dsn = "mesh.db"
	}
	token := os.Getenv("MESH_NETWORK_TOKEN")
	bootstrapToken := os.Getenv("MESH_ACCOUNT_BOOTSTRAP_TOKEN")
	if token != "" && len(token) < 24 {
		log.Fatal("MESH_NETWORK_TOKEN must contain at least 24 characters")
	}
	if bootstrapToken != "" && len(bootstrapToken) < 24 {
		log.Fatal("MESH_ACCOUNT_BOOTSTRAP_TOKEN must contain at least 24 characters")
	}
	db, e := sql.Open("sqlite", dsn)
	if e != nil {
		log.Fatal(e)
	}
	// SQLite permits one writer. Keep one process-local connection and make it
	// wait for an external lock instead of failing concurrent heartbeat and
	// topology requests with SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, e = db.Exec("PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL"); e != nil {
		log.Fatal(e)
	}
	s := &server{
		db: db, token: token, bootstrapToken: bootstrapToken, ttl: int64(envInt("MESH_NODE_TTL_SECONDS", 45)),
		auto: envInt("MESH_AUTO_SUPERPEERS", 0), backboneDegree: envInt("MESH_BACKBONE_DEGREE", 6),
		clientLinks: envInt("MESH_CLIENT_LINKS", 2), symmetricLinks: envInt("MESH_SYMMETRIC_LINKS", 3),
		sessions:        map[string]map[string]*rendezvousPeer{},
		controls:        map[*controlClient]string{},
		metrics:         map[string]linkMetric{},
		inviteAttempts:  map[string][]time.Time{},
		accountAttempts: map[string][]time.Time{},
	}
	_, s.network, _ = net.ParseCIDR(value("MESH_IP_NETWORK", "10.77.0.0/24"))
	if e = s.init(); e != nil {
		log.Fatal(e)
	}
	if s.bootstrapToken == "" && s.token != "" {
		s.bootstrapToken = s.token
	}
	if s.bootstrapToken == "" {
		var users int
		if e = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); e != nil {
			log.Fatal(e)
		}
		if users == 0 {
			s.bootstrapToken, e = randomToken(32)
			if e != nil {
				log.Fatal(e)
			}
			log.Printf("[SERVER] FIRST ACCOUNT REGISTRATION TOKEN: %s", s.bootstrapToken)
			log.Printf("[SERVER] enter this token in the Registration invite field at /admin; it is not stored in the database")
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/auth/register", s.accountRegister)
	mux.HandleFunc("POST /v1/auth/login", s.accountLogin)
	mux.HandleFunc("POST /v1/auth/logout", s.accountLogout)
	mux.HandleFunc("POST /v1/auth/token/rotate", s.rotateAccountToken)
	mux.HandleFunc("GET /v1/auth/me", s.accountMe)
	mux.HandleFunc("GET /v1/admin/account-invites", s.accountInvite)
	mux.HandleFunc("POST /v1/admin/account-invites", s.accountInvite)
	mux.Handle("/v1/ws", websocket.Server{
		Handler: websocket.Handler(s.controlWS),
		Handshake: func(_ *websocket.Config, r *http.Request) error {
			if !s.networkTokenValid(r) {
				if !s.allowInviteAttempt(r.RemoteAddr) || !s.consumeInvite(r.Header.Get("X-Mesh-Invite")) {
					return fmt.Errorf("unauthorized")
				}
			}
			return nil
		},
	})
	mux.HandleFunc("GET /v1/bootstrap/{node_id}", s.bootstrap)
	mux.HandleFunc("POST /v1/services", s.service)
	mux.HandleFunc("GET /v1/services/{node_id}/{name}", s.serviceDetails)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("GET /admin.css", s.adminAsset)
	mux.HandleFunc("GET /admin-interactive.css", s.adminAsset)
	mux.HandleFunc("GET /admin.js", s.adminAsset)
	mux.HandleFunc("GET /v1/admin/config", s.adminConfig)
	mux.HandleFunc("PUT /v1/admin/config", s.adminConfig)
	mux.HandleFunc("GET /v1/admin/topology", s.adminTopology)
	mux.HandleFunc("POST /v1/telemetry", s.telemetry)
	mux.HandleFunc("GET /v1/admin/audit", s.adminAudit)
	mux.HandleFunc("GET /v1/admin/invites", s.adminInvite)
	mux.HandleFunc("POST /v1/admin/invites", s.adminInvite)
	mux.HandleFunc("DELETE /v1/admin/nodes/{node_id}", s.adminNode)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/role", s.adminNodeRole)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/network", s.adminNodeNetwork)
	mux.HandleFunc("POST /v1/admin/nodes/{node_id}/network/routes", s.adminAddNodeRoute)
	mux.HandleFunc("DELETE /v1/admin/nodes/{node_id}/network/routes", s.adminRemoveNodeRoute)
	mux.HandleFunc("GET /v1/admin/graph", s.adminGraph)
	mux.HandleFunc("PUT /v1/admin/graph", s.adminGraph)
	// Legacy endpoints intentionally stay unauthenticated: the experimental
	// punch client predates the mesh network token and can use this coordinator.
	mux.HandleFunc("POST /register", s.rendezvousRegister)
	mux.HandleFunc("GET /wait", s.rendezvousWait)
	port := value("MESH_PORT", "8001")
	log.Printf("[SERVER] starting on 0.0.0.0:%s", port)
	server := &http.Server{
		Addr: ":" + port, Handler: securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	if cert, key := os.Getenv("MESH_TLS_CERT"), os.Getenv("MESH_TLS_KEY"); cert != "" || key != "" {
		if cert == "" || key == "" {
			log.Fatal("MESH_TLS_CERT and MESH_TLS_KEY must be set together")
		}
		log.Fatal(server.ListenAndServeTLS(cert, key))
	}
	log.Printf("[SERVER] WARNING: TLS is disabled; use HTTPS/reverse proxy before exposing login endpoints")
	log.Fatal(server.ListenAndServe())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// controlFrame is deliberately small: after the upgrade all control-plane
// requests share one TCP/TLS connection, avoiding repeated HTTP handshakes.
type controlFrame struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Status int             `json:"status,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
}

func (s *server) controlWS(ws *websocket.Conn) {
	credential := ws.Request().Header.Get("X-Mesh-Token")
	if credential == "" {
		credential = s.token
	}
	client := &controlClient{c: ws, invited: ws.Request().Header.Get("X-Mesh-Invite") != "", credential: credential}
	defer func() {
		s.controlMu.Lock()
		delete(s.controls, client)
		s.controlMu.Unlock()
		ws.Close()
	}()
	for {
		var in controlFrame
		if err := websocket.JSON.Receive(ws, &in); err != nil {
			return
		}
		out := s.controlRequestWithToken(in, client.credential)
		if client.invited && in.Method == http.MethodPost && in.Path == "/v1/register" && out.Status >= 200 && out.Status < 300 {
			var body map[string]any
			_ = json.Unmarshal(out.Body, &body)
			body["network_token"] = s.token
			out.Body, _ = json.Marshal(body)
			client.invited = false
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
				s.controls[client] = registration.ID
				s.controlMu.Unlock()
				s.pushTopologies()
			}
		}
	}
}

func (c *controlClient) send(frame controlFrame) error {
	c.ws.Lock()
	defer c.ws.Unlock()
	return websocket.JSON.Send(c.c, frame)
}

// pushTopologies sends only to connected nodes, so a topology change becomes
// visible immediately instead of waiting for a node's periodic refresh.
func (s *server) pushTopologies() {
	s.controlMu.Lock()
	clients := make(map[*controlClient]string, len(s.controls))
	for client, id := range s.controls {
		clients[client] = id
	}
	s.controlMu.Unlock()
	for client, id := range clients {
		out := s.controlRequestWithToken(controlFrame{Method: http.MethodGet, Path: "/v1/bootstrap/" + id}, client.credential)
		if out.Status >= 200 && out.Status < 300 {
			out.Event = "topology"
			_ = client.send(out)
		}
	}
}

// Reuse the validated HTTP handlers so both transports have exactly the same
// authorization, validation and database semantics. The HTTP API remains for
// older nodes and operational tooling.
func (s *server) controlRequest(in controlFrame) controlFrame {
	return s.controlRequestWithToken(in, s.token)
}

func (s *server) controlRequestWithToken(in controlFrame, credential string) controlFrame {
	if in.Method == "" || in.Path == "" {
		return controlFrame{Status: http.StatusBadRequest, Error: "missing method or path"}
	}
	r := httptest.NewRequest(in.Method, "http://control"+in.Path, bytes.NewReader(in.Body))
	if credential != "" {
		r.Header.Set("X-Mesh-Token", credential)
	}
	w := httptest.NewRecorder()
	switch {
	case in.Method == http.MethodPost && in.Path == "/v1/register":
		s.register(w, r)
	case in.Method == http.MethodPost && in.Path == "/v1/services":
		s.service(w, r)
	case in.Method == http.MethodPost && in.Path == "/v1/telemetry":
		s.telemetry(w, r)
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
	result := w.Result()
	defer result.Body.Close()
	body := json.RawMessage(append([]byte(nil), w.Body.Bytes()...))
	if result.StatusCode < 200 || result.StatusCode > 299 {
		return controlFrame{Status: result.StatusCode, Error: strings.TrimSpace(string(body))}
	}
	return controlFrame{Status: result.StatusCode, Body: body}
}
func value(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func (s *server) init() error {
	_, err := s.db.Exec(`PRAGMA foreign_keys = ON; CREATE TABLE IF NOT EXISTS nodes (node_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,nat_type TEXT NOT NULL,role TEXT NOT NULL,endpoint TEXT NOT NULL,requested_role TEXT NOT NULL DEFAULT 'auto',relay_capable INTEGER NOT NULL DEFAULT 1,capacity INTEGER NOT NULL DEFAULT 1,last_seen INTEGER NOT NULL,created_at INTEGER NOT NULL,mesh_ip TEXT,owner_id INTEGER REFERENCES users(id));CREATE TABLE IF NOT EXISTS services (node_id TEXT NOT NULL,name TEXT NOT NULL,target_host TEXT NOT NULL,target_port INTEGER NOT NULL,allowed_nodes TEXT NOT NULL DEFAULT '*',PRIMARY KEY(node_id,name));CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER);CREATE TABLE IF NOT EXISTS audit_log (created_at INTEGER NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL);CREATE TABLE IF NOT EXISTS graph_links (a TEXT NOT NULL,b TEXT NOT NULL,cost REAL NOT NULL DEFAULT 1,PRIMARY KEY(a,b));CREATE TABLE IF NOT EXISTS role_overrides (node_id TEXT PRIMARY KEY,role TEXT NOT NULL);CREATE TABLE IF NOT EXISTS node_network (node_id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',routes TEXT NOT NULL DEFAULT '[]',dns_ip TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS dns_records(node_id TEXT NOT NULL,name TEXT NOT NULL UNIQUE,lan_ip TEXT NOT NULL,PRIMARY KEY(node_id,name));CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL COLLATE NOCASE UNIQUE,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL,last_login_at INTEGER,disabled INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS account_tokens (token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,revoked_at INTEGER);CREATE INDEX IF NOT EXISTS account_tokens_user_idx ON account_tokens(user_id);CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY,csrf_hash TEXT NOT NULL,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER);CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id);CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);CREATE TABLE IF NOT EXISTS account_invites (token_hash TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER);`)
	if err != nil {
		return err
	}
	rows, err := s.db.Query("PRAGMA table_info(nodes)")
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	// Migration statements below must run after the schema cursor releases the
	// sole connection from the pool.
	if err = rows.Close(); err != nil {
		return err
	}
	if !columns["mesh_ip"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN mesh_ip TEXT"); err != nil {
			return err
		}
	}
	if !columns["owner_id"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN owner_id INTEGER"); err != nil {
			return err
		}
	}
	if !columns["requested_role"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN requested_role TEXT"); err != nil {
			return err
		}
		if _, err = s.db.Exec("UPDATE nodes SET requested_role = CASE WHEN role = 'superpeer' THEN 'superpeer' ELSE 'auto' END"); err != nil {
			return err
		}
	}
	if !columns["relay_capable"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN relay_capable INTEGER NOT NULL DEFAULT 1"); err != nil {
			return err
		}
	}
	return s.loadSettings()
}

const (
	sessionCookieName = "mesh_session"
	csrfCookieName    = "mesh_csrf"
	sessionLifetime   = 12 * time.Hour
	bcryptCost        = 12
)

// This is only used to make a login for an unknown username perform the same
// expensive password operation as a login for a real account. It is not a
// credential and is never accepted for an account.
var dummyPasswordHash = func() string {
	hash, err := bcrypt.GenerateFromPassword([]byte("mesh-invalid-login-sentinel"), bcryptCost)
	if err != nil {
		panic("could not initialize password timing sentinel")
	}
	return string(hash)
}()

type authenticatedUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 || strings.ToLower(username) != username {
		return false
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validPassword(password string) bool {
	// bcrypt deliberately rejects passwords longer than 72 bytes. Rejecting
	// them here avoids silently ignoring a user's password suffix.
	return len(password) >= 12 && len(password) <= 72
}

func tokenDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(bytesLen int) (string, error) {
	raw := make([]byte, bytesLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func requestHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

// Keep account creation and password guessing bounded per source address.
// This is intentionally process-local; HTTPS deployments should also put a
// coarse rate limit at the reverse proxy for multi-instance deployments.
func (s *server) allowAccountAttempt(r *http.Request) bool {
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)
	host := requestHost(r)
	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	if s.accountAttempts == nil {
		s.accountAttempts = map[string][]time.Time{}
	}
	old := s.accountAttempts[host]
	kept := old[:0]
	for _, attempt := range old {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	if len(kept) >= 10 {
		s.accountAttempts[host] = kept
		return false
	}
	s.accountAttempts[host] = append(kept, now)
	return true
}

func (s *server) sessionUser(r *http.Request) (authenticatedUser, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" || s.db == nil {
		return authenticatedUser{}, false
	}
	digest := tokenDigest(cookie.Value)
	var user authenticatedUser
	var expires int64
	var revoked sql.NullInt64
	err = s.db.QueryRow(`SELECT u.id,u.username,s.expires_at,s.revoked_at
		FROM auth_sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=? AND u.disabled=0`, digest).Scan(&user.ID, &user.Username, &expires, &revoked)
	if err != nil || revoked.Valid || expires < time.Now().Unix() {
		if err == nil && (revoked.Valid || expires < time.Now().Unix()) {
			_, _ = s.db.Exec("DELETE FROM auth_sessions WHERE token_hash=?", digest)
		}
		return authenticatedUser{}, false
	}
	return user, true
}

func (s *server) setAccountCookies(w http.ResponseWriter, r *http.Request, session, csrf string, expires time.Time) {
	secure := r.TLS != nil || strings.EqualFold(os.Getenv("MESH_COOKIE_SECURE"), "true")
	http.SetCookie(w, &http.Cookie{ // session token is never exposed to JavaScript.
		Name: sessionCookieName, Value: session, Path: "/", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{ // the CSRF token is intentionally readable by same-origin JS.
		Name: csrfCookieName, Value: csrf, Path: "/", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), Secure: secure, SameSite: http.SameSiteStrictMode,
	})
}

func clearAccountCookies(w http.ResponseWriter, r *http.Request) {
	secure := r.TLS != nil || strings.EqualFold(os.Getenv("MESH_COOKIE_SECURE"), "true")
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: name == sessionCookieName, Secure: secure, SameSite: http.SameSiteStrictMode})
	}
}

func (s *server) csrfValid(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	provided := r.Header.Get("X-CSRF-Token")
	// Older embedded admin.js versions already send X-Mesh-Token on every
	// request. For a session, the UI replaces that value with the CSRF token;
	// accepting it as a fallback keeps that client backwards-compatible while
	// retaining the same double-submit validation.
	if provided == "" {
		provided = r.Header.Get("X-Mesh-Token")
	}
	if len(provided) == 0 || len(provided) != len(cookie.Value) || subtle.ConstantTimeCompare([]byte(provided), []byte(cookie.Value)) != 1 {
		return false
	}
	// Bind the double-submit token to the server-side session as well. This
	// prevents a cookie planted by an unrelated subdomain from being enough.
	session, err := r.Cookie(sessionCookieName)
	if err != nil || session.Value == "" {
		return false
	}
	var stored string
	err = s.db.QueryRow("SELECT csrf_hash FROM auth_sessions WHERE token_hash=? AND revoked_at IS NULL", tokenDigest(session.Value)).Scan(&stored)
	return err == nil && subtle.ConstantTimeCompare([]byte(stored), []byte(tokenDigest(provided))) == 1
}

func (s *server) adminAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.networkTokenValid(r) {
		return true
	}
	if _, ok := s.sessionUser(r); !ok {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.csrfValid(r) {
		reply(w, http.StatusForbidden, map[string]string{"error": "csrf validation failed"})
		return false
	}
	return true
}

func (s *server) accountRegister(w http.ResponseWriter, r *http.Request) {
	if !s.allowAccountAttempt(r) {
		reply(w, http.StatusTooManyRequests, map[string]string{"error": "too many account attempts; try again later"})
		return
	}
	var d struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Invite   string `json:"invite_token"`
	}
	if decodeJSON(w, r, &d) != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid registration request"})
		return
	}
	d.Username = strings.ToLower(strings.TrimSpace(d.Username))
	if !validUsername(d.Username) || !validPassword(d.Password) {
		reply(w, http.StatusBadRequest, map[string]string{"error": "username or password does not meet the requirements"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(d.Password), bcryptCost)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not secure password"})
		return
	}
	networkToken, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create account token"})
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not start registration"})
		return
	}
	defer tx.Rollback()
	var users int
	if err = tx.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not inspect accounts"})
		return
	}
	if users > 0 {
		if d.Invite == "" {
			reply(w, http.StatusForbidden, map[string]string{"error": "registration requires an administrator invitation"})
			return
		}
		result, updateErr := tx.Exec("UPDATE account_invites SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>=?", time.Now().Unix(), tokenDigest(d.Invite), time.Now().Unix())
		if updateErr != nil {
			reply(w, http.StatusInternalServerError, map[string]string{"error": "could not validate invitation"})
			return
		}
		used, rowsErr := result.RowsAffected()
		if rowsErr != nil || used != 1 {
			reply(w, http.StatusForbidden, map[string]string{"error": "invalid or expired invitation"})
			return
		}
	} else {
		// Bootstrap is deliberately tied to an operator-held secret. Without
		// this check, the first internet client could race to become the first
		// administrator account on a fresh coordinator.
		bootstrap := s.bootstrapToken
		if bootstrap == "" {
			bootstrap = s.token
		}
		if bootstrap == "" || len(d.Invite) != len(bootstrap) || subtle.ConstantTimeCompare([]byte(d.Invite), []byte(bootstrap)) != 1 {
			reply(w, http.StatusForbidden, map[string]string{"error": "first registration requires the coordinator bootstrap token"})
			return
		}
	}
	now := time.Now().Unix()
	result, err := tx.Exec("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", d.Username, string(hash), now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			reply(w, http.StatusConflict, map[string]string{"error": "username is already registered"})
		} else {
			reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create account"})
		}
		return
	}
	userID, err := result.LastInsertId()
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not complete registration"})
		return
	}
	if _, err = tx.Exec("INSERT INTO account_tokens(token_hash,user_id,created_at) VALUES(?,?,?)", tokenDigest(networkToken), userID, now); err != nil || tx.Commit() != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not complete registration"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_registered", fmt.Sprintf("user_id=%d username=%s", userID, d.Username))
	reply(w, http.StatusCreated, map[string]any{"status": "created", "username": d.Username, "network_token": networkToken})
}

func (s *server) accountLogin(w http.ResponseWriter, r *http.Request) {
	if !s.allowAccountAttempt(r) {
		reply(w, http.StatusTooManyRequests, map[string]string{"error": "too many account attempts; try again later"})
		return
	}
	var d struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &d) != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid login request"})
		return
	}
	d.Username = strings.ToLower(strings.TrimSpace(d.Username))
	var user authenticatedUser
	var passwordHash string
	var disabled int
	err := s.db.QueryRow("SELECT id,username,password_hash,disabled FROM users WHERE username=?", d.Username).Scan(&user.ID, &user.Username, &passwordHash, &disabled)
	if err != nil {
		passwordHash = dummyPasswordHash
	}
	passwordOK := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(d.Password)) == nil
	if err != nil || disabled != 0 || !passwordOK {
		reply(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	session, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	now := time.Now()
	expires := now.Add(sessionLifetime)
	if _, err = s.db.Exec("INSERT INTO auth_sessions(token_hash,csrf_hash,user_id,created_at,expires_at) VALUES(?,?,?,?,?)", tokenDigest(session), tokenDigest(csrf), user.ID, now.Unix(), expires.Unix()); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not save session"})
		return
	}
	_, _ = s.db.Exec("UPDATE users SET last_login_at=? WHERE id=?", now.Unix(), user.ID)
	_, _ = s.db.Exec("DELETE FROM auth_sessions WHERE expires_at<? OR revoked_at IS NOT NULL", now.Unix())
	s.setAccountCookies(w, r, session, csrf, expires)
	reply(w, http.StatusOK, map[string]any{"authenticated": true, "username": user.Username, "expires_at": expires.Unix()})
}

func (s *server) accountLogout(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		_, _ = s.db.Exec("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=?", time.Now().Unix(), tokenDigest(cookie.Value))
	}
	clearAccountCookies(w, r)
	reply(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (s *server) rotateAccountToken(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	userID, scoped := s.accountIDForRequest(r)
	if !scoped {
		reply(w, http.StatusForbidden, map[string]string{"error": "only an account can rotate its token"})
		return
	}
	token, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create account token"})
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not rotate account token"})
		return
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err = tx.Exec("UPDATE account_tokens SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", now, userID); err == nil {
		_, err = tx.Exec("INSERT INTO account_tokens(token_hash,user_id,created_at) VALUES(?,?,?)", tokenDigest(token), userID, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not rotate account token"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_token_rotated", fmt.Sprintf("user_id=%d", userID))
	reply(w, http.StatusOK, map[string]any{"network_token": token, "rotated_at": now})
}

func (s *server) accountMe(w http.ResponseWriter, r *http.Request) {
	if user, ok := s.sessionUser(r); ok {
		reply(w, http.StatusOK, map[string]any{"authenticated": true, "username": user.Username})
		return
	}
	if s.networkTokenValid(r) {
		if userID, ok := s.accountTokenUser(r); ok {
			reply(w, http.StatusOK, map[string]any{"authenticated": true, "auth_type": "account_token", "user_id": userID})
			return
		}
		reply(w, http.StatusOK, map[string]any{"authenticated": true, "auth_type": "legacy_network_token"})
		return
	}
	reply(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// accountTokenUser resolves a per-account bearer token. Raw tokens are never
// stored; the client keeps the returned token and passes it as X-Mesh-Token,
// exactly like the unchanged mesh-node client already does.
func (s *server) accountTokenUser(r *http.Request) (int64, bool) {
	provided := r.Header.Get("X-Mesh-Token")
	if provided == "" || s.db == nil {
		return 0, false
	}
	var userID int64
	err := s.db.QueryRow(`SELECT t.user_id FROM account_tokens t JOIN users u ON u.id=t.user_id
		WHERE t.token_hash=? AND t.revoked_at IS NULL AND u.disabled=0`, tokenDigest(provided)).Scan(&userID)
	if err != nil {
		return 0, false
	}
	return userID, true
}

func (s *server) accountIDForRequest(r *http.Request) (int64, bool) {
	if user, ok := s.sessionUser(r); ok {
		return user.ID, true
	}
	return s.accountTokenUser(r)
}

func (s *server) nodeOwnedByAccount(nodeID string, accountID int64) bool {
	var owner sql.NullInt64
	if err := s.db.QueryRow("SELECT owner_id FROM nodes WHERE node_id=?", nodeID).Scan(&owner); err != nil {
		return false
	}
	return owner.Valid && owner.Int64 == accountID
}

func (s *server) requireNodeAccess(w http.ResponseWriter, r *http.Request, nodeID string) bool {
	if accountID, scoped := s.accountIDForRequest(r); scoped && !s.nodeOwnedByAccount(nodeID, accountID) {
		reply(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return false
	}
	return true
}

func (s *server) auth(w http.ResponseWriter, r *http.Request) bool {
	if !s.networkTokenValid(r) {
		reply(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

func (s *server) networkTokenValid(r *http.Request) bool {
	provided := r.Header.Get("X-Mesh-Token")
	if len(provided) != 0 && len(provided) == len(s.token) && subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1 {
		return true
	}
	_, ok := s.accountTokenUser(r)
	return ok
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

const maxJSONBody = 64 << 10

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}

type topologySettings struct {
	TTL            int `json:"node_ttl_seconds"`
	AutoSuperpeers int `json:"auto_superpeers"`
	BackboneDegree int `json:"backbone_degree"`
	ClientLinks    int `json:"client_links"`
	SymmetricLinks int `json:"symmetric_links"`
}

func (s *server) settings() topologySettings {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return topologySettings{int(s.ttl), s.auto, s.backboneDegree, s.clientLinks, s.symmetricLinks}
}

func (s *server) loadSettings() error {
	settings := s.settings()
	rows, err := s.db.Query("SELECT key,value FROM settings")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var value int
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		switch key {
		case "node_ttl_seconds":
			settings.TTL = value
		case "auto_superpeers":
			settings.AutoSuperpeers = value
		case "backbone_degree":
			settings.BackboneDegree = value
		case "client_links":
			settings.ClientLinks = value
		case "symmetric_links":
			settings.SymmetricLinks = value
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := validSettings(settings); err != nil {
		return fmt.Errorf("stored topology settings: %w", err)
	}
	s.configMu.Lock()
	s.ttl = int64(settings.TTL)
	s.auto = settings.AutoSuperpeers
	s.backboneDegree = settings.BackboneDegree
	s.clientLinks = settings.ClientLinks
	s.symmetricLinks = settings.SymmetricLinks
	s.configMu.Unlock()
	return nil
}

func validSettings(c topologySettings) error {
	if c.TTL < 10 || c.TTL > 3600 {
		return fmt.Errorf("node_ttl_seconds must be between 10 and 3600")
	}
	if c.AutoSuperpeers < 0 || c.AutoSuperpeers > 10000 {
		return fmt.Errorf("auto_superpeers must be between 0 and 10000")
	}
	if c.BackboneDegree < 1 || c.BackboneDegree > 128 {
		return fmt.Errorf("backbone_degree must be between 1 and 128")
	}
	if c.ClientLinks < 1 || c.ClientLinks > 32 || c.SymmetricLinks < 1 || c.SymmetricLinks > 32 {
		return fmt.Errorf("client_links and symmetric_links must be between 1 and 32")
	}
	return nil
}

func (s *server) adminConfig(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		reply(w, http.StatusOK, s.settings())
		return
	}
	if _, scoped := s.accountIDForRequest(r); scoped {
		reply(w, http.StatusForbidden, map[string]string{"error": "topology policy is coordinator-wide and can only be changed with the legacy administrator credential"})
		return
	}
	var next topologySettings
	if err := decodeJSON(w, r, &next); err != nil || validSettings(next) != nil {
		message := "invalid topology settings"
		if err != nil {
			message = err.Error()
		} else {
			message = validSettings(next).Error()
		}
		reply(w, http.StatusBadRequest, map[string]string{"error": message})
		return
	}
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES('node_ttl_seconds',?),('auto_superpeers',?),('backbone_degree',?),('client_links',?),('symmetric_links',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next.TTL, next.AutoSuperpeers, next.BackboneDegree, next.ClientLinks, next.SymmetricLinks)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.configMu.Lock()
	s.ttl = int64(next.TTL)
	s.auto = next.AutoSuperpeers
	s.backboneDegree = next.BackboneDegree
	s.clientLinks = next.ClientLinks
	s.symmetricLinks = next.SymmetricLinks
	s.configMu.Unlock()
	if err := s.rebalanceRoles(); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.pushTopologies()
	reply(w, http.StatusOK, next)
}

// rebalanceRoles makes an auto-superpeer setting take effect immediately for
// already registered nodes, not only when their next heartbeat arrives.
func (s *server) rebalanceRoles() error {
	return s.rebalanceRolesFor(nil)
}

func (s *server) rebalanceRolesFor(ownerID *int64) error {
	c := s.settings()
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=?"
	args := []any{time.Now().Unix() - int64(c.TTL)}
	if ownerID != nil {
		query += " AND owner_id=?"
		args = append(args, *ownerID)
	}
	nodes, err := s.rows(query, args...)
	if err != nil {
		return err
	}
	manual, candidates := 0, make([]node, 0, len(nodes))
	for _, n := range nodes {
		if n.RequestedRole == "superpeer" {
			manual++
			continue
		}
		if n.RequestedRole == "auto" && n.NAT == "cone" && n.Relay {
			candidates = append(candidates, n)
		}
	}
	target := c.AutoSuperpeers
	if target == 0 {
		target = intSqrtCeil(len(candidates))
	}
	target = max(0, target-manual)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Capacity != candidates[j].Capacity {
			return candidates[i].Capacity > candidates[j].Capacity
		}
		if candidates[i].CreatedAt != candidates[j].CreatedAt {
			return candidates[i].CreatedAt < candidates[j].CreatedAt
		}
		return candidates[i].ID < candidates[j].ID
	})
	super := map[string]bool{}
	for _, n := range nodes {
		if n.RequestedRole == "superpeer" {
			super[n.ID] = true
		}
	}
	for _, n := range candidates[:min(target, len(candidates))] {
		super[n.ID] = true
	}
	for _, n := range nodes {
		role := "client"
		if super[n.ID] {
			role = "superpeer"
		}
		if _, err := s.db.Exec("UPDATE nodes SET role=? WHERE node_id=?", role, n.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) adminTopology(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ttl := s.settings().TTL
	now := time.Now().Unix()
	scope := r.URL.Query().Get("scope")
	all := scope == "all"
	accountID, scoped := s.accountIDForRequest(r)
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=?"
	args := []any{now - int64(ttl)}
	if all {
		query = "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes"
		args = nil
	}
	if scoped {
		query += " WHERE owner_id=?"
		args = append(args, accountID)
		if !all {
			query = strings.Replace(query, " WHERE last_seen>=? WHERE owner_id=?", " WHERE last_seen>=? AND owner_id=?", 1)
		}
	}
	query += " ORDER BY node_id"
	nodes, err := s.rows(query, args...)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.enrichNodes(nodes)
	for i := range nodes {
		nodes[i].UptimeSeconds = now - nodes[i].CreatedAt
		if nodes[i].UptimeSeconds < 0 {
			nodes[i].UptimeSeconds = 0
		}
		nodes[i].Online = nodes[i].LastSeen >= now-int64(ttl)
	}
	links := s.links(nodes)
	if all {
		// Keep the live topology based on online nodes, but expose stored manual
		// links to offline nodes so they can still be edited in the graph.
		online := make([]node, 0, len(nodes))
		for _, n := range nodes {
			if n.Online {
				online = append(online, n)
			}
		}
		links = s.links(online)
		seen := map[string]bool{}
		for _, e := range links {
			seen[edgeKey(e.A, e.B)] = true
		}
		missing := []link{}
		for _, e := range s.manualLinksForNodes(nodes) {
			if !seen[edgeKey(e.A, e.B)] {
				missing = append(missing, e)
			}
		}
		links = append(links, s.decorateLinks(missing, nodes)...)
	}
	reply(w, http.StatusOK, map[string]any{"scope": map[bool]string{true: "all", false: "online"}[all], "nodes": nodes, "links": links, "settings": s.settings()})
}

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

func parseRouteAds(raw string) []routeAdvertisement {
	var routes []routeAdvertisement
	if json.Unmarshal([]byte(raw), &routes) == nil && routes != nil {
		return routes
	}
	var legacy []string
	if json.Unmarshal([]byte(raw), &legacy) == nil {
		for _, lan := range legacy {
			routes = append(routes, routeAdvertisement{LAN: lan})
		}
	}
	return routes
}

func translatedIP(raw string, routes []routeAdvertisement, toVirtual bool) string {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return ""
	}
	for _, r := range routes {
		lan, e1 := netip.ParsePrefix(r.LAN)
		virtual, e2 := netip.ParsePrefix(r.Virtual)
		if e1 != nil || e2 != nil {
			continue
		}
		from, to := lan, virtual
		if !toVirtual {
			from, to = virtual, lan
		}
		if from.Contains(ip) {
			a := ip.As4()
			b := from.Addr().As4()
			c := to.Addr().As4()
			offset := binary.BigEndian.Uint32(a[:]) - binary.BigEndian.Uint32(b[:])
			v := binary.BigEndian.Uint32(c[:]) + offset
			var out [4]byte
			binary.BigEndian.PutUint32(out[:], v)
			return netip.AddrFrom4(out).String()
		}
	}
	return ""
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

func (s *server) adminNodeNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var d struct {
		Name       string      `json:"name"`
		Routes     []string    `json:"routes"`
		DNSRecords []dnsRecord `json:"dns_records"`
	}
	if decodeJSON(w, r, &d) != nil {
		reply(w, 400, map[string]string{"error": "invalid network settings"})
		return
	}
	d.Name = strings.ToLower(strings.TrimSpace(d.Name))
	if !validDNSName(d.Name) {
		reply(w, 400, map[string]string{"error": "name must contain only lowercase letters, digits and hyphens"})
		return
	}
	seen := map[string]bool{}
	for i, raw := range d.Routes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !p.Addr().Is4() {
			reply(w, 400, map[string]string{"error": "routes must be IPv4 CIDRs"})
			return
		}
		p = p.Masked()
		if p.Bits() < 16 || p.Bits() > 30 {
			reply(w, 400, map[string]string{"error": "LAN routes must have prefixes between /16 and /30"})
			return
		}
		d.Routes[i] = p.String()
		if seen[d.Routes[i]] {
			reply(w, 400, map[string]string{"error": "duplicate route"})
			return
		}
		seen[d.Routes[i]] = true
	}
	rows, err := s.db.Query("SELECT node_id,routes FROM node_network")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	used := []netip.Prefix{}
	old := map[string]string{}
	for rows.Next() {
		var other, raw string
		_ = rows.Scan(&other, &raw)
		for _, route := range parseRouteAds(raw) {
			if other == id {
				old[route.LAN] = route.Virtual
			} else if p, e := netip.ParsePrefix(route.Virtual); e == nil {
				used = append(used, p)
			}
		}
	}
	rows.Close()
	meshPrefix, _ := netip.ParsePrefix(s.network.String())
	used = append(used, meshPrefix)
	allocated := make([]routeAdvertisement, 0, len(d.Routes))
	for _, lan := range d.Routes {
		bits := mustPrefix(lan).Bits()
		virtual := old[lan]
		if p, e := netip.ParsePrefix(virtual); e != nil || prefixOverlapsAny(p, used) {
			virtual = ""
		}
		if virtual == "" {
			virtual = allocateVirtual(bits, used)
			if virtual == "" {
				reply(w, 409, map[string]string{"error": "10.77.0.0/16 virtual address pool is exhausted"})
				return
			}
		}
		p, _ := netip.ParsePrefix(virtual)
		used = append(used, p)
		allocated = append(allocated, routeAdvertisement{LAN: lan, Virtual: virtual})
	}
	var exists int
	if s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", id).Scan(&exists) != nil {
		reply(w, 404, map[string]string{"error": "unknown node"})
		return
	}
	if d.Name != "" {
		var owner string
		_ = s.db.QueryRow("SELECT node_id FROM node_network WHERE name=? AND node_id!=?", d.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "name already used"})
			return
		}
		_ = s.db.QueryRow("SELECT node_id FROM dns_records WHERE name=? AND node_id!=?", d.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "name already used by a LAN object"})
			return
		}
	}
	names := map[string]bool{}
	for i := range d.DNSRecords {
		r := &d.DNSRecords[i]
		r.Name = strings.ToLower(strings.TrimSpace(r.Name))
		r.IP = strings.TrimSpace(r.IP)
		if !validDNSName(r.Name) || r.Name == "" || names[r.Name] || r.Name == d.Name {
			reply(w, 400, map[string]string{"error": "invalid or duplicate DNS object name"})
			return
		}
		names[r.Name] = true
		if translatedIP(r.IP, allocated, true) == "" {
			reply(w, 400, map[string]string{"error": fmt.Sprintf("DNS object %s is outside advertised LAN routes", r.Name)})
			return
		}
		r.VirtualIP = translatedIP(r.IP, allocated, true)
		var owner string
		_ = s.db.QueryRow("SELECT node_id FROM dns_records WHERE name=? AND node_id!=?", r.Name, id).Scan(&owner)
		if owner != "" {
			reply(w, 409, map[string]string{"error": "DNS name already used"})
			return
		}
		_ = s.db.QueryRow("SELECT node_id FROM node_network WHERE name=?", r.Name).Scan(&owner)
		if owner != "" && owner != id {
			reply(w, 409, map[string]string{"error": "DNS name already used"})
			return
		}
	}
	raw, _ := json.Marshal(allocated)
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO node_network(node_id,name,routes,dns_ip) VALUES(?,?,?,'') ON CONFLICT(node_id) DO UPDATE SET name=excluded.name,routes=excluded.routes,dns_ip=''", id, d.Name, string(raw)); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = tx.Exec("DELETE FROM dns_records WHERE node_id=?", id)
	for _, record := range d.DNSRecords {
		if _, err = tx.Exec("INSERT INTO dns_records(node_id,name,lan_ip) VALUES(?,?,?)", id, record.Name, record.IP); err != nil {
			reply(w, 409, map[string]string{"error": err.Error()})
			return
		}
	}
	_, _ = tx.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_network", fmt.Sprintf("node=%s name=%s routes=%s", id, d.Name, string(raw)))
	if err = tx.Commit(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.pushTopologies()
	reply(w, 200, map[string]any{"name": d.Name, "routes": allocated, "dns_records": d.DNSRecords})
}

type routeChange struct {
	Route string `json:"route"`
}

func parseLANRoute(raw string) (string, netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !p.Addr().Is4() {
		return "", netip.Prefix{}, errors.New("route must be an IPv4 CIDR")
	}
	p = p.Masked()
	if p.Bits() < 16 || p.Bits() > 30 {
		return "", netip.Prefix{}, errors.New("LAN route prefix must be between /16 and /30")
	}
	return p.String(), p, nil
}

func (s *server) adminAddNodeRoute(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var change routeChange
	if err := decodeJSON(w, r, &change); err != nil {
		reply(w, 400, map[string]string{"error": "invalid route request"})
		return
	}
	lan, prefix, err := parseLANRoute(change.Route)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var exists int
	if s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", id).Scan(&exists) != nil {
		reply(w, 404, map[string]string{"error": "unknown node"})
		return
	}
	var name, raw string
	_ = s.db.QueryRow("SELECT name,routes FROM node_network WHERE node_id=?", id).Scan(&name, &raw)
	routes := parseRouteAds(raw)
	for _, route := range routes {
		if route.LAN == lan {
			reply(w, 409, map[string]string{"error": "route already advertised"})
			return
		}
	}
	rows, err := s.db.Query("SELECT node_id,routes FROM node_network")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	used := []netip.Prefix{}
	for rows.Next() {
		var owner, encoded string
		if rows.Scan(&owner, &encoded) == nil {
			for _, route := range parseRouteAds(encoded) {
				if virtual, e := netip.ParsePrefix(route.Virtual); e == nil {
					used = append(used, virtual)
				}
			}
		}
	}
	rows.Close()
	if mesh, e := netip.ParsePrefix(s.network.String()); e == nil {
		used = append(used, mesh)
	}
	virtual := allocateVirtual(prefix.Bits(), used)
	if virtual == "" {
		reply(w, 409, map[string]string{"error": "10.77.0.0/16 virtual address pool is exhausted"})
		return
	}
	routes = append(routes, routeAdvertisement{LAN: lan, Virtual: virtual})
	encoded, _ := json.Marshal(routes)
	_, err = s.db.Exec("INSERT INTO node_network(node_id,name,routes,dns_ip) VALUES(?,?,?,'') ON CONFLICT(node_id) DO UPDATE SET routes=excluded.routes", id, name, string(encoded))
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_route_added", fmt.Sprintf("node=%s route=%s virtual=%s", id, lan, virtual))
	s.pushTopologies()
	reply(w, 200, map[string]any{"route": routeAdvertisement{LAN: lan, Virtual: virtual}})
}

func (s *server) adminRemoveNodeRoute(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var change routeChange
	if err := decodeJSON(w, r, &change); err != nil {
		reply(w, 400, map[string]string{"error": "invalid route request"})
		return
	}
	lan, _, err := parseLANRoute(change.Route)
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var name, raw string
	if err := s.db.QueryRow("SELECT name,routes FROM node_network WHERE node_id=?", id).Scan(&name, &raw); err != nil {
		reply(w, 404, map[string]string{"error": "node has no advertised routes"})
		return
	}
	old := parseRouteAds(raw)
	remaining := make([]routeAdvertisement, 0, len(old))
	found := false
	for _, route := range old {
		if route.LAN == lan {
			found = true
			continue
		}
		remaining = append(remaining, route)
	}
	if !found {
		reply(w, 404, map[string]string{"error": "route is not advertised"})
		return
	}
	encoded, _ := json.Marshal(remaining)
	if _, err = s.db.Exec("UPDATE node_network SET routes=?,dns_ip='' WHERE node_id=?", string(encoded), id); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// DNS objects whose physical address belonged to the revoked LAN are no
	// longer valid and must not remain advertised with a stale virtual IP.
	rows, _ := s.db.Query("SELECT name,lan_ip FROM dns_records WHERE node_id=?", id)
	if rows != nil {
		for rows.Next() {
			var dnsName, lanIP string
			if rows.Scan(&dnsName, &lanIP) == nil && translatedIP(lanIP, remaining, true) == "" {
				_, _ = s.db.Exec("DELETE FROM dns_records WHERE node_id=? AND name=?", id, dnsName)
			}
		}
		rows.Close()
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_route_removed", fmt.Sprintf("node=%s route=%s", id, lan))
	s.pushTopologies()
	reply(w, 200, map[string]any{"removed": lan, "routes": remaining})
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

func metricKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}
func (s *server) telemetry(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var report struct {
		NodeID string `json:"node_id"`
		Links  []struct {
			PeerID string  `json:"peer_id"`
			RTTMS  float64 `json:"rtt_ms"`
			Up     bool    `json:"up"`
		} `json:"links"`
	}
	if err := decodeJSON(w, r, &report); err != nil || report.NodeID == "" {
		reply(w, 400, map[string]string{"error": "invalid telemetry"})
		return
	}
	if !s.requireNodeAccess(w, r, report.NodeID) {
		return
	}
	now := time.Now()
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	for _, x := range report.Links {
		if x.PeerID == "" || x.PeerID == report.NodeID {
			continue
		}
		k := metricKey(report.NodeID, x.PeerID)
		old := s.metrics[k]
		if x.RTTMS > 0 && x.RTTMS < 60000 {
			if old.RTTMS == 0 {
				old.RTTMS = x.RTTMS
			} else {
				old.RTTMS = old.RTTMS*.7 + x.RTTMS*.3
			}
		}
		old.Up = x.Up
		old.Seen = now
		s.metrics[k] = old
	}
	reply(w, 200, map[string]string{"status": "ok"})
}
func (s *server) adminAudit(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if _, scoped := s.accountIDForRequest(r); scoped {
		// Legacy audit rows predate account ownership. Returning them to an
		// account would disclose other tenants' node IDs and operations.
		reply(w, http.StatusOK, []map[string]any{})
		return
	}
	rows, err := s.db.Query("SELECT created_at,event,detail FROM audit_log ORDER BY created_at DESC LIMIT 30")
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at int64
		var event, detail string
		if rows.Scan(&at, &event, &detail) == nil {
			out = append(out, map[string]any{"created_at": at, "event": event, "detail": detail})
		}
	}
	reply(w, 200, out)
}
func (s *server) decorateLinks(links []link, nodes ...[]node) []link {
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	now := time.Now()
	uptime := map[string]int64{}
	if len(nodes) > 0 {
		for _, n := range nodes[0] {
			uptime[n.ID] = max64(0, now.Unix()-n.CreatedAt)
		}
	}
	for i := range links {
		m := s.metrics[metricKey(links[i].A, links[i].B)]
		baseCost := links[i].Cost
		if baseCost <= 0 {
			baseCost = 1
		}
		if m.RTTMS > 0 {
			links[i].RTTMS = m.RTTMS
			// Keep the configured/manual weight as a base, then add the
			// measured latency. This makes cost useful for both automatic and
			// manually edited graphs instead of silently replacing it.
			links[i].Cost = baseCost * (1 + m.RTTMS/1000)
		} else {
			links[i].Cost = baseCost
		}
		// New nodes have less observed uptime, so keep them slightly less
		// attractive until they prove stable. The factor converges to 1.
		if ua, oka := uptime[links[i].A]; oka {
			if ub, okb := uptime[links[i].B]; okb {
				hours := float64(min64(ua, ub)) / 3600
				links[i].Cost *= 1 + 1/(1+hours)
			}
		}
		if m.Up && now.Sub(m.Seen) < 45*time.Second {
			links[i].Status = "up"
		} else {
			links[i].Status = "down"
			// A stale/down link remains visible for diagnostics but is made
			// expensive enough that routing avoids it while telemetry recovers.
			links[i].Cost *= 4
		}
	}
	return links
}

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

func (s *server) consumeInvite(token string) bool {
	if len(token) != 6 {
		return false
	}
	now := time.Now().Unix()
	result, err := s.db.Exec("UPDATE invites SET used_at=? WHERE token=? AND used_at IS NULL AND expires_at>=?", now, token, now)
	if err != nil {
		return false
	}
	count, err := result.RowsAffected()
	return err == nil && count == 1
}

// Five failed invite attempts per IP per 30 seconds keeps a short human
// friendly code practical without making it a brute-force credential.
func (s *server) allowInviteAttempt(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()
	cutoff := now.Add(-30 * time.Second)
	s.inviteMu.Lock()
	defer s.inviteMu.Unlock()
	old := s.inviteAttempts[host]
	kept := old[:0]
	for _, t := range old {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= 5 {
		s.inviteAttempts[host] = kept
		return false
	}
	s.inviteAttempts[host] = append(kept, now)
	return true
}

func (s *server) adminInvite(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if _, scoped := s.accountIDForRequest(r); scoped {
		if r.Method == http.MethodGet {
			reply(w, http.StatusOK, []map[string]any{})
		} else {
			reply(w, http.StatusForbidden, map[string]string{"error": "mesh nodes use the account network token; legacy setup keys require the coordinator administrator"})
		}
		return
	}
	if r.Method == http.MethodGet {
		rows, err := s.db.Query("SELECT token,created_at,expires_at,used_at FROM invites WHERE expires_at>=? ORDER BY created_at DESC", time.Now().Unix())
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var token string
			var created, expires int64
			var used sql.NullInt64
			if err = rows.Scan(&token, &created, &expires, &used); err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
			out = append(out, map[string]any{"token": token, "created_at": created, "expires_at": expires, "used": used.Valid})
		}
		reply(w, 200, out)
		return
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var token string
	for {
		var raw [6]byte
		if _, err := rand.Read(raw[:]); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		b := make([]byte, 6)
		for i := range b {
			b[i] = alphabet[int(raw[i])%len(alphabet)]
		}
		token = string(b)
		var exists int
		_ = s.db.QueryRow("SELECT 1 FROM invites WHERE token=?", token).Scan(&exists)
		if exists == 0 {
			break
		}
	}
	now := time.Now().Unix()
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at) VALUES(?,?,?)", token, now, now+30); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "invite_created", token)
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": now + 30, "expires_in_seconds": 30})
}

// accountInvite manages high-entropy invitations for human accounts. The
// short setup keys above remain dedicated to enrolling mesh nodes.
func (s *server) accountInvite(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	now := time.Now().Unix()
	if r.Method == http.MethodGet {
		rows, err := s.db.Query("SELECT created_at,expires_at,used_at FROM account_invites WHERE expires_at>=? OR used_at IS NOT NULL ORDER BY created_at DESC LIMIT 50", now)
		if err != nil {
			reply(w, http.StatusInternalServerError, map[string]string{"error": "could not list account invitations"})
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var created, expires int64
			var used sql.NullInt64
			if err = rows.Scan(&created, &expires, &used); err != nil {
				reply(w, http.StatusInternalServerError, map[string]string{"error": "could not list account invitations"})
				return
			}
			out = append(out, map[string]any{"created_at": created, "expires_at": expires, "used": used.Valid})
		}
		reply(w, http.StatusOK, out)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token, err := randomToken(32)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not create invitation"})
		return
	}
	expires := now + 24*60*60
	if _, err = s.db.Exec("INSERT INTO account_invites(token_hash,created_at,expires_at) VALUES(?,?,?)", tokenDigest(token), now, expires); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not save invitation"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_invite_created", "account invitation created")
	// The raw token is returned exactly once and is never logged or stored.
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": expires, "expires_in_seconds": 24 * 60 * 60})
}

func (s *server) adminNode(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	if id == "" {
		reply(w, 400, map[string]string{"error": "missing node_id"})
		return
	}
	result, err := s.db.Exec("DELETE FROM nodes WHERE node_id=?", id)
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		reply(w, 404, map[string]string{"error": "node not found"})
		return
	}
	_, _ = s.db.Exec("DELETE FROM services WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM role_overrides WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM node_network WHERE node_id=?", id)
	_, _ = s.db.Exec("DELETE FROM dns_records WHERE node_id=?", id)
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "node_deleted", id)
	s.pushTopologies()
	reply(w, 200, map[string]string{"status": "deleted"})
}

func (s *server) adminNodeRole(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	if !s.requireNodeAccess(w, r, id) {
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &input); err != nil || (input.Role != "auto" && input.Role != "client" && input.Role != "superpeer") {
		reply(w, 400, map[string]string{"error": "role must be auto, client or superpeer"})
		return
	}
	var nat string
	if err := s.db.QueryRow("SELECT nat_type FROM nodes WHERE node_id=?", id).Scan(&nat); err != nil {
		reply(w, 404, map[string]string{"error": "node not found"})
		return
	}
	if input.Role == "superpeer" && nat != "cone" {
		reply(w, 409, map[string]string{"error": "only cone NAT nodes can be superpeers"})
		return
	}
	if _, err := s.db.Exec("INSERT INTO role_overrides(node_id,role) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET role=excluded.role", id, input.Role); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.db.Exec("UPDATE nodes SET requested_role=? WHERE node_id=?", input.Role, id); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if accountID, scoped := s.accountIDForRequest(r); scoped {
		if err := s.rebalanceRolesFor(&accountID); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
	} else if err := s.rebalanceRoles(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "role_changed", id+":"+input.Role)
	s.pushTopologies()
	reply(w, 200, map[string]string{"status": "ok", "role": input.Role})
}

func (s *server) adminGraph(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	accountID, scoped := s.accountIDForRequest(r)
	if r.Method == http.MethodGet {
		reply(w, 200, map[string]any{"links": s.manualLinksForAccount(accountID, scoped)})
		return
	}
	var input struct {
		Links []link `json:"links"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	for _, e := range input.Links {
		if e.A == "" || e.B == "" || e.A == e.B || e.Cost <= 0 || e.Cost > 1000 {
			reply(w, 400, map[string]string{"error": "invalid graph link"})
			return
		}
		if scoped && (!s.nodeOwnedByAccount(e.A, accountID) || !s.nodeOwnedByAccount(e.B, accountID)) {
			reply(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()
	if scoped {
		_, err = tx.Exec("DELETE FROM graph_links WHERE a IN (SELECT node_id FROM nodes WHERE owner_id=?) AND b IN (SELECT node_id FROM nodes WHERE owner_id=?)", accountID, accountID)
	} else {
		_, err = tx.Exec("DELETE FROM graph_links")
	}
	if err == nil {
		for _, e := range input.Links {
			a, b := e.A, e.B
			if a > b {
				a, b = b, a
			}
			if _, err = tx.Exec("INSERT OR REPLACE INTO graph_links(a,b,cost) VALUES(?,?,?)", a, b, e.Cost); err != nil {
				break
			}
		}
	}
	if err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err = tx.Commit(); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	s.pushTopologies()
	reply(w, 200, map[string]any{"links": input.Links})
}

func (s *server) manualLinks() []link {
	return s.manualLinksForAccount(0, false)
}

func (s *server) manualLinksForAccount(accountID int64, scoped bool) []link {
	if s.db == nil {
		return []link{}
	}
	query := "SELECT a,b,cost FROM graph_links ORDER BY a,b"
	args := []any{}
	if scoped {
		query = `SELECT g.a,g.b,g.cost FROM graph_links g
			JOIN nodes na ON na.node_id=g.a JOIN nodes nb ON nb.node_id=g.b
			WHERE na.owner_id=? AND nb.owner_id=? ORDER BY g.a,g.b`
		args = []any{accountID, accountID}
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return []link{}
	}
	defer rows.Close()
	out := []link{}
	for rows.Next() {
		var e link
		if rows.Scan(&e.A, &e.B, &e.Cost) == nil {
			out = append(out, e)
		}
	}
	return out
}

func (s *server) adminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, adminPageHTML)
}
func (s *server) adminAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	switch r.URL.Path {
	case "/admin.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, adminCSS)
	case "/admin-interactive.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, adminInteractiveCSS)
	case "/admin.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = io.WriteString(w, adminJS)
	default:
		http.NotFound(w, r)
	}
}

/* Legacy inline admin UI retained temporarily for source-history context.

const adminExtras = `<section id="tools"><h2>Invitations</h2><button onclick="createInvite()">Create 30-second invite</button><code id="invite"></code><h2>Manual graph</h2><p>One edge per line: <code>NODE_ID_A NODE_ID_B COST</code>. Save an empty field to restore automatic topology.</p><textarea id="graph" rows="8" style="width:100%;background:#1c2635;color:#e6edf3"></textarea><br><button onclick="loadGraph()">Load graph</button><button onclick="saveGraph()">Save and push graph</button><h2>Remove device</h2><select id="removeNode"></select><button onclick="removeNode()">Remove selected device</button></section><script>async function createInvite(){try{let x=await api('/v1/admin/invites',{method:'POST'});document.getElementById('invite').textContent=' Invite: '+x.invite_token+' (valid 30 seconds)'}catch(e){$('status').textContent='Error: '+e.message}}async function loadGraph(){try{let x=await api('/v1/admin/graph');$('graph').value=(x.links||[]).map(e=>e.a+' '+e.b+' '+e.cost).join('\n')}catch(e){$('status').textContent='Error: '+e.message}}async function saveGraph(){try{let links=$('graph').value.trim()?$('graph').value.trim().split(/\n+/).map(line=>{let p=line.trim().split(/\s+/);if(p.length!==3)throw Error('Each edge requires two IDs and cost');return {a:p[0],b:p[1],cost:Number(p[2])}}):[];await api('/v1/admin/graph',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({links})});$('status').textContent='Manual graph applied';loadAll()}catch(e){$('status').textContent='Error: '+e.message}}async function removeNode(){let id=$('removeNode').value;if(!id)return;try{await api('/v1/admin/nodes/'+encodeURIComponent(id),{method:'DELETE'});$('status').textContent='Device removed';loadAll();refreshDevices()}catch(e){$('status').textContent='Error: '+e.message}}async function refreshDevices(){try{let t=await api('/v1/admin/topology');$('removeNode').innerHTML=(t.nodes||[]).map(n=>'<option value="'+n.node_id+'">'+n.node_id.slice(0,12)+' — '+n.mesh_ip+'</option>').join('')}catch(e){}}let baseLoad=loadAll;loadAll=async()=>{await baseLoad();refreshDevices()};</script>`

const adminHTML = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mesh coordinator</title><style>body{max-width:960px;margin:2rem auto;padding:0 1rem;font:16px system-ui;background:#10151e;color:#e6edf3}input,button{padding:.55rem;margin:.25rem;background:#1c2635;color:inherit;border:1px solid #40516a;border-radius:4px}button{cursor:pointer;background:#2463a5}label{display:inline-block;margin:.4rem}#status{min-height:1.5rem;color:#8dd3ff}table{width:100%;border-collapse:collapse;margin-top:1rem}td,th{padding:.45rem;text-align:left;border-bottom:1px solid #35445a;font-size:.9rem}code{font-size:.8rem}</style><h1>Mesh coordinator</h1><p>Токен остаётся только в памяти вкладки и отправляется в заголовке API.</p><label>Network token <input id="token" type="password" size="42" autocomplete="off"></label><button onclick="loadAll()">Подключиться / обновить</button><p id="status"></p><h2>Топология</h2><form id="settings"><label>TTL, сек <input name="node_ttl_seconds" type="number" min="10" max="3600"></label><label>Авто superpeer (0=√n) <input name="auto_superpeers" type="number" min="0"></label><label>Backbone degree <input name="backbone_degree" type="number" min="1" max="128"></label><label>Links client <input name="client_links" type="number" min="1" max="32"></label><label>Links symmetric <input name="symmetric_links" type="number" min="1" max="32"></label><button>Применить и разослать</button></form><h2>Активные узлы</h2><div id="summary"></div><table><thead><tr><th>ID</th><th>Роль</th><th>NAT</th><th>Mesh IP</th><th>Endpoint</th><th>Связи</th></tr></thead><tbody id="nodes"></tbody></table><script>const $=id=>document.getElementById(id),api=async(p,o={})=>{o.headers={...(o.headers||{}),'X-Mesh-Token':$('token').value};let r=await fetch(p,o),x=await r.json();if(!r.ok)throw Error(x.error||r.status);return x};function esc(x){let d=document.createElement('i');d.textContent=x;return d.innerHTML}async function loadAll(){try{let [c,t]=await Promise.all([api('/v1/admin/config'),api('/v1/admin/topology')]);for(let k in c)$('settings').elements[k].value=c[k];let links={};for(let e of t.links){(links[e.a]??=[]).push(e.b.slice(0,8));(links[e.b]??=[]).push(e.a.slice(0,8))}$('summary').textContent='Узлов: '+t.nodes.length+'; связей: '+t.links.length;$('nodes').innerHTML=t.nodes.map(n=>'<tr><td><code>'+esc(n.node_id.slice(0,12))+'</code></td><td>'+esc(n.role)+'</td><td>'+esc(n.nat_type)+'</td><td>'+esc(n.mesh_ip)+'</td><td>'+esc(n.endpoint)+'</td><td><code>'+esc((links[n.node_id]||[]).join(', '))+'</code></td></tr>').join('');$('status').textContent='Обновлено'}catch(e){$('status').textContent='Ошибка: '+e.message}}$('settings').onsubmit=async e=>{e.preventDefault();try{let o={};for(let x of new FormData(e.target))o[x[0]]=Number(x[1]);await api('/v1/admin/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(o)});$('status').textContent='Настройки применены и отправлены узлам';loadAll()}catch(x){$('status').textContent='Ошибка: '+x.message}}</script>`

*/

func (s *server) rows(query string, args ...any) ([]node, error) {
	rs, e := s.db.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rs.Close()
	a := []node{}
	for rs.Next() {
		var n node
		var relay int
		if e = rs.Scan(&n.ID, &n.PublicKey, &n.NAT, &n.Role, &n.Endpoint, &n.RequestedRole, &relay, &n.Capacity, &n.LastSeen, &n.CreatedAt, &n.MeshIP); e != nil {
			return nil, e
		}
		n.Relay = relay != 0
		a = append(a, n)
	}
	return a, rs.Err()
}
func (s *server) allocate() (string, error) {
	rows, e := s.db.Query("SELECT mesh_ip FROM nodes WHERE mesh_ip IS NOT NULL")
	if e != nil {
		return "", e
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var x string
		rows.Scan(&x)
		used[x] = true
	}
	ip := append(net.IP(nil), s.network.IP...)
	for inc(ip); s.network.Contains(ip); inc(ip) {
		if !used[ip.String()] {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("mesh address pool is exhausted")
}
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}
func (s *server) assign(id, requested, nat string, relay bool, capacity int, now int64) (string, error) {
	s.configMu.RLock()
	ttl, auto := s.ttl, s.auto
	s.configMu.RUnlock()
	if requested == "superpeer" {
		return "superpeer", nil
	}
	if requested == "client" || nat != "cone" || !relay {
		return "client", nil
	}
	all, e := s.rows("SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=? AND node_id!=?", now-ttl, id)
	if e != nil {
		return "", e
	}
	manual := 0
	var c []node
	for _, n := range all {
		if n.RequestedRole == "superpeer" {
			manual++
		}
		if n.RequestedRole == "auto" && n.NAT == "cone" && n.Relay {
			c = append(c, n)
		}
	}
	target := auto
	if target == 0 {
		// sqrt grows the backbone slowly while still giving a small network
		// redundancy. Manual superpeers are counted separately below.
		target = intSqrtCeil(len(c))
	}
	slots := target - manual
	if slots <= 0 {
		return "client", nil
	}
	var created int64 = now
	s.db.QueryRow("SELECT created_at FROM nodes WHERE node_id=?", id).Scan(&created)
	c = append(c, node{ID: id, Capacity: capacity, CreatedAt: created})
	sort.Slice(c, func(i, j int) bool {
		if c[i].Capacity != c[j].Capacity {
			return c[i].Capacity > c[j].Capacity
		}
		if c[i].CreatedAt != c[j].CreatedAt {
			return c[i].CreatedAt < c[j].CreatedAt
		}
		return c[i].ID < c[j].ID
	})
	for _, n := range c[:min(slots, len(c))] {
		if n.ID == id {
			return "superpeer", nil
		}
	}
	return "client", nil
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
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	accountID, accountScoped := s.accountIDForRequest(r)
	var d struct {
		ID       string `json:"node_id"`
		Public   string `json:"public_key"`
		NAT      string `json:"nat_type"`
		Role     string `json:"role"`
		Endpoint string `json:"endpoint"`
		MeshIP   string `json:"mesh_ip"`
		Capacity int    `json:"capacity"`
		Relay    *bool  `json:"relay_capable"`
	}
	if decodeJSON(w, r, &d) != nil || d.ID == "" || len(d.ID) > 128 || d.Public == "" || len(d.Public) > 256 || d.Endpoint == "" || len(d.Endpoint) > 256 || !(d.NAT == "cone" || d.NAT == "symmetric") || !(d.Role == "auto" || d.Role == "client" || d.Role == "superpeer") {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
		return
	}
	if _, _, err := net.SplitHostPort(d.Endpoint); err != nil {
		reply(w, 400, map[string]any{"error": "invalid endpoint"})
		return
	}
	pub, e := protocol.B64Decode(d.Public)
	if e != nil || protocol.NodeID(pub) != d.ID {
		reply(w, 400, map[string]any{"error": "node_id does not match public_key"})
		return
	}
	var existingOwner sql.NullInt64
	if s.db.QueryRow("SELECT owner_id FROM nodes WHERE node_id=?", d.ID).Scan(&existingOwner) == nil && accountScoped && existingOwner.Valid && existingOwner.Int64 != accountID {
		reply(w, http.StatusForbidden, map[string]any{"error": "node belongs to another account"})
		return
	}
	var roleOverride string
	if s.db.QueryRow("SELECT role FROM role_overrides WHERE node_id=?", d.ID).Scan(&roleOverride) == nil {
		d.Role = roleOverride
	}
	if d.Role == "superpeer" && d.NAT != "cone" {
		reply(w, 400, map[string]any{"error": "only cone nodes may be superpeers"})
		return
	}
	if d.MeshIP != "" && net.ParseIP(d.MeshIP).To4() == nil {
		reply(w, 400, map[string]any{"error": "invalid mesh_ip"})
		return
	}
	relay := true
	if d.Relay != nil {
		relay = *d.Relay
	}
	if d.Capacity < 1 {
		d.Capacity = 1
	}
	if d.Capacity > 1000 {
		d.Capacity = 1000
	}
	now := time.Now().Unix()
	var old sql.NullString
	s.db.QueryRow("SELECT mesh_ip FROM nodes WHERE node_id=?", d.ID).Scan(&old)
	ip := d.MeshIP
	if ip == "" && old.Valid {
		ip = old.String
	}
	if ip == "" {
		ip, e = s.allocate()
		if e != nil {
			reply(w, 500, map[string]any{"error": e.Error()})
			return
		}
	}
	var owner string
	var ownerLastSeen int64
	s.db.QueryRow("SELECT node_id,last_seen FROM nodes WHERE mesh_ip=? AND node_id!=?", ip, d.ID).Scan(&owner, &ownerLastSeen)
	if owner != "" {
		if ownerLastSeen >= now-int64(s.settings().TTL) {
			reply(w, 409, map[string]any{"error": "mesh_ip is already assigned"})
			return
		}
		// A crashed or replaced client may leave its last mesh address in the
		// registry. It is safe to reclaim it once the previous registration is
		// outside the online TTL; keep the old device row for offline inventory.
		if _, e = s.db.Exec("UPDATE nodes SET mesh_ip='' WHERE node_id=?", owner); e != nil {
			reply(w, 500, map[string]any{"error": e.Error()})
			return
		}
	}
	role, e := s.assign(d.ID, d.Role, d.NAT, relay, d.Capacity, now)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	var ownerValue any
	if accountScoped {
		ownerValue = accountID
	}
	_, e = s.db.Exec(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET public_key=excluded.public_key,nat_type=excluded.nat_type,role=excluded.role,endpoint=excluded.endpoint,requested_role=excluded.requested_role,relay_capable=excluded.relay_capable,capacity=excluded.capacity,last_seen=excluded.last_seen,mesh_ip=excluded.mesh_ip,owner_id=COALESCE(nodes.owner_id,excluded.owner_id)`, d.ID, d.Public, d.NAT, role, d.Endpoint, d.Role, boolInt(relay), d.Capacity, now, now, ip, ownerValue)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	if accountScoped {
		e = s.rebalanceRolesFor(&accountID)
	} else {
		e = s.rebalanceRoles()
	}
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	_ = s.db.QueryRow("SELECT role FROM nodes WHERE node_id=?", d.ID).Scan(&role)
	log.Printf("[SERVER] register node=%s role=%s mesh_ip=%s", d.ID[:8], role, ip)
	reply(w, 200, map[string]any{"status": "ok", "mesh_ip": ip, "mesh_network": s.network.String(), "assigned_role": role})
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *server) rendezvousRegister(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Session  string `json:"session"`
		ID       string `json:"id"`
		External string `json:"external"`
		NATType  string `json:"nat_type"`
	}
	if decodeJSON(w, r, &request) != nil || len(request.Session) == 0 || len(request.Session) > 128 || len(request.ID) == 0 || len(request.ID) > 128 || request.External == "" || len(request.External) > 256 || (request.NATType != "cone" && request.NATType != "symmetric") {
		reply(w, http.StatusBadRequest, map[string]any{"error": "missing or invalid fields"})
		return
	}
	if _, _, err := net.SplitHostPort(request.External); err != nil {
		reply(w, http.StatusBadRequest, map[string]any{"error": "invalid external endpoint"})
		return
	}

	s.sessionsMu.Lock()
	peers := s.sessions[request.Session]
	if peers == nil {
		peers = map[string]*rendezvousPeer{}
		s.sessions[request.Session] = peers
	}
	peers[request.ID] = &rendezvousPeer{endpoint: request.External, natType: request.NATType, status: "waiting", ready: make(chan struct{})}
	if len(peers) == 2 {
		ids := make([]string, 0, 2)
		for id := range peers {
			ids = append(ids, id)
		}
		first, second := peers[ids[0]], peers[ids[1]]
		if first.natType == "symmetric" && second.natType == "symmetric" {
			for _, peer := range peers {
				peer.status = "incompatible"
				close(peer.ready)
			}
		} else {
			first.status, first.other, first.otherNAT = "ready", second.endpoint, second.natType
			second.status, second.other, second.otherNAT = "ready", first.endpoint, first.natType
			close(first.ready)
			close(second.ready)
		}
	}
	s.sessionsMu.Unlock()
	log.Printf("[SERVER] rendezvous register session=%s peer=%s nat=%s", request.Session, request.ID, request.NATType)
	reply(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) rendezvousWait(w http.ResponseWriter, r *http.Request) {
	session, id := r.URL.Query().Get("session"), r.URL.Query().Get("id")
	timeout, err := strconv.Atoi(r.URL.Query().Get("timeout"))
	if err != nil || timeout <= 0 {
		timeout = 30
	}
	timeout = min(timeout, 120)
	s.sessionsMu.Lock()
	peer := s.sessions[session][id]
	s.sessionsMu.Unlock()
	if peer == nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "not registered"})
		return
	}
	select {
	case <-peer.ready:
	case <-time.After(time.Duration(timeout) * time.Second):
		reply(w, http.StatusRequestTimeout, map[string]string{"status": "timeout"})
		return
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if peer.status == "incompatible" {
		reply(w, http.StatusConflict, map[string]string{"status": "incompatible", "error": "symmetric-symmetric is unsupported"})
		return
	}
	if peer.status != "ready" {
		reply(w, http.StatusRequestTimeout, map[string]string{"status": "timeout"})
		return
	}
	reply(w, http.StatusOK, map[string]string{"status": "ready", "peer": peer.other, "peer_nat_type": peer.otherNAT})
}
func topologyVersion(nodes []node) string {
	var a []string
	for _, n := range nodes {
		a = append(a, strings.Join([]string{n.ID, n.PublicKey, n.NAT, n.Role, n.Endpoint, n.MeshIP, strconv.Itoa(n.Capacity)}, ":"))
	}
	h := sha256.Sum256([]byte(strings.Join(a, "|")))
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
func (s *server) telemetryPeerOrder(client node, peers []node) []node {
	rank := append([]node(nil), peers...)
	s.metricsMu.RLock()
	defer s.metricsMu.RUnlock()
	sort.Slice(rank, func(i, j int) bool {
		a, b := s.metrics[metricKey(client.ID, rank[i].ID)], s.metrics[metricKey(client.ID, rank[j].ID)]
		freshA := a.Up && time.Since(a.Seen) < 45*time.Second
		freshB := b.Up && time.Since(b.Seen) < 45*time.Second
		if freshA != freshB {
			return freshA
		}
		ra, rb := a.RTTMS, b.RTTMS
		if ra == 0 {
			ra = 1e9
		}
		if rb == 0 {
			rb = 1e9
		}
		if ra != rb {
			return ra < rb
		}
		if rank[i].Capacity != rank[j].Capacity {
			return rank[i].Capacity > rank[j].Capacity
		}
		return rank[i].ID < rank[j].ID
	})
	return rank
}
func (s *server) links(nodes []node) []link {
	if manual := s.manualLinksForNodes(nodes); len(manual) > 0 {
		return s.decorateLinks(s.addAutomaticClientLinks(manual, nodes), nodes)
	}
	s.configMu.RLock()
	backboneDegree, clientLinks, symmetricLinks := s.backboneDegree, s.clientLinks, s.symmetricLinks
	s.configMu.RUnlock()
	var sp []node
	for _, n := range nodes {
		if n.Role == "superpeer" {
			sp = append(sp, n)
		}
	}
	out := []link{}
	degree := min(max(1, backboneDegree), len(sp)-1)
	seen := map[string]bool{}
	for i, n := range sp {
		for step := 1; step <= degree/2; step++ {
			a, b := n.ID, sp[(i+step)%len(sp)].ID
			if a > b {
				a, b = b, a
			}
			k := a + ":" + b
			if !seen[k] {
				seen[k] = true
				out = append(out, link{A: a, B: b, Cost: 1})
			}
		}
		if degree%2 == 1 && len(sp)%2 == 0 {
			a, b := n.ID, sp[(i+len(sp)/2)%len(sp)].ID
			if a > b {
				a, b = b, a
			}
			k := a + ":" + b
			if !seen[k] {
				seen[k] = true
				out = append(out, link{A: a, B: b, Cost: 1})
			}
		}
	}
	for _, n := range nodes {
		if n.Role != "client" {
			continue
		}
		linkCount := clientLinks
		if n.NAT == "symmetric" {
			linkCount = symmetricLinks
		}
		rank := s.telemetryPeerOrder(n, sp)
		for i, p := range rank[:min(linkCount, len(rank))] {
			out = append(out, link{A: n.ID, B: p.ID, Cost: 1 + float64(i)/10})
		}
	}
	return s.decorateLinks(out, nodes)
}

func (s *server) manualLinksForNodes(nodes []node) []link {
	allowed := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		allowed[n.ID] = true
	}
	out := []link{}
	for _, e := range s.manualLinks() {
		if allowed[e.A] && allowed[e.B] {
			out = append(out, e)
		}
	}
	return out
}

func edgeKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + ":" + b
}

// addAutomaticClientLinks preserves manually managed backbone edges while
// still attaching every client to the nearest available superpeers. Without
// this merge, adding any manual graph edge disables all automatic client
// attachments, leaving newly registered nodes with neighbors=0.
func (s *server) addAutomaticClientLinks(out []link, nodes []node) []link {
	s.configMu.RLock()
	clientLinks, symmetricLinks := s.clientLinks, s.symmetricLinks
	s.configMu.RUnlock()
	var superpeers []node
	for _, n := range nodes {
		if n.Role == "superpeer" {
			superpeers = append(superpeers, n)
		}
	}
	if len(superpeers) == 0 {
		return out
	}
	for _, client := range nodes {
		if client.Role != "client" {
			continue
		}
		want := clientLinks
		if client.NAT == "symmetric" {
			want = symmetricLinks
		}
		connected := map[string]bool{}
		for _, edge := range out {
			if edge.A == client.ID {
				connected[edge.B] = true
			}
			if edge.B == client.ID {
				connected[edge.A] = true
			}
		}
		count := 0
		for _, peer := range superpeers {
			if connected[peer.ID] {
				count++
			}
		}
		for _, peer := range s.telemetryPeerOrder(client, superpeers) {
			if count >= want {
				break
			}
			if connected[peer.ID] {
				continue
			}
			out = append(out, link{A: client.ID, B: peer.ID, Cost: 1 + float64(count)/10})
			connected[peer.ID] = true
			count++
		}
	}
	return out
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func (s *server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	id := r.PathValue("node_id")
	ttl := s.settings().TTL
	accountID, scoped := s.accountIDForRequest(r)
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,mesh_ip FROM nodes WHERE last_seen>=?"
	args := []any{time.Now().Unix() - int64(ttl)}
	if scoped {
		query += " AND owner_id=?"
		args = append(args, accountID)
	}
	query += " ORDER BY node_id"
	all, e := s.rows(query, args...)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	s.enrichNodes(all)
	var self *node
	for i := range all {
		if all[i].ID == id {
			self = &all[i]
		}
	}
	if self == nil {
		reply(w, 404, map[string]any{"error": "unknown node"})
		return
	}
	ls := s.links(all)
	neighbors := map[string]bool{}
	for _, l := range ls {
		if l.A == id {
			neighbors[l.B] = true
		}
		if l.B == id {
			neighbors[l.A] = true
		}
	}
	var peers []node
	for _, n := range all {
		if neighbors[n.ID] {
			peers = append(peers, n)
		}
	}
	serviceQuery := "SELECT services.node_id,services.name FROM services JOIN nodes ON nodes.node_id=services.node_id"
	serviceArgs := []any{}
	if scoped {
		serviceQuery += " WHERE nodes.owner_id=?"
		serviceArgs = append(serviceArgs, accountID)
	}
	serviceQuery += " ORDER BY services.node_id,services.name"
	rs, _ := s.db.Query(serviceQuery, serviceArgs...)
	var services []map[string]string
	for rs.Next() {
		var n, x string
		rs.Scan(&n, &x)
		services = append(services, map[string]string{"node_id": n, "name": x})
	}
	rs.Close()
	reply(w, 200, map[string]any{"topology_version": topologyVersion(all), "self": self, "neighbors": peers, "directory": all, "backbone_links": ls, "services": services, "graph_update_mode": "reserved"})
}
func (s *server) service(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	var d struct {
		Node    string `json:"node_id"`
		Name    string `json:"name"`
		Host    string `json:"target_host"`
		Port    int    `json:"target_port"`
		Allowed string `json:"allowed_nodes"`
	}
	if decodeJSON(w, r, &d) != nil || d.Node == "" || len(d.Node) > 128 || d.Name == "" || len(d.Name) > 128 || d.Host == "" || len(d.Host) > 253 || d.Port < 1 || d.Port > 65535 {
		reply(w, 400, map[string]any{"error": "missing or invalid required fields"})
		return
	}
	var x int
	e := s.db.QueryRow("SELECT 1 FROM nodes WHERE node_id=?", d.Node).Scan(&x)
	if e != nil {
		reply(w, 404, map[string]any{"error": "unknown node"})
		return
	}
	if !s.requireNodeAccess(w, r, d.Node) {
		return
	}
	if d.Allowed == "" {
		d.Allowed = "*"
	}
	_, e = s.db.Exec(`INSERT INTO services(node_id,name,target_host,target_port,allowed_nodes) VALUES(?,?,?,?,?) ON CONFLICT(node_id,name) DO UPDATE SET target_host=excluded.target_host,target_port=excluded.target_port,allowed_nodes=excluded.allowed_nodes`, d.Node, d.Name, d.Host, d.Port, d.Allowed)
	if e != nil {
		reply(w, 500, map[string]any{"error": e.Error()})
		return
	}
	reply(w, 200, map[string]any{"status": "ok"})
}
func (s *server) serviceDetails(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	if !s.requireNodeAccess(w, r, r.PathValue("node_id")) {
		return
	}
	var d struct {
		Node, Name, Host, Allowed string
		Port                      int
	}
	e := s.db.QueryRow("SELECT node_id,name,target_host,target_port,allowed_nodes FROM services WHERE node_id=? AND name=?", r.PathValue("node_id"), r.PathValue("name")).Scan(&d.Node, &d.Name, &d.Host, &d.Port, &d.Allowed)
	if e != nil {
		reply(w, 404, map[string]any{"error": "service not found"})
		return
	}
	reply(w, 200, map[string]any{"node_id": d.Node, "name": d.Name, "target_host": d.Host, "target_port": d.Port, "allowed_nodes": d.Allowed})
}
