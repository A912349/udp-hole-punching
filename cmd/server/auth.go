package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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

func (s *server) loadTokenKey() error {
	var key []byte
	err := s.db.QueryRow("SELECT value FROM server_secrets WHERE name='account_token_key'").Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		if _, err = s.db.Exec("INSERT INTO server_secrets(name,value) VALUES('account_token_key',?)", key); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if len(key) != 32 {
		return errors.New("invalid account token encryption key")
	}
	s.tokenKey = key
	return nil
}

func (s *server) encryptAccountToken(raw string) ([]byte, error) {
	block, err := aes.NewCipher(s.tokenKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(raw), nil), nil
}

func (s *server) decryptAccountToken(encoded []byte) (string, error) {
	block, err := aes.NewCipher(s.tokenKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encoded) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted account token")
	}
	nonce, ciphertext := encoded[:gcm.NonceSize()], encoded[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
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

// accountRegister creates an account using an authorized one-time invite.
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
	encryptedToken, err := s.encryptAccountToken(networkToken)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not protect account token"})
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
	if _, err = tx.Exec("INSERT INTO account_tokens(token_hash,user_id,encrypted_token,created_at) VALUES(?,?,?,?)", tokenDigest(networkToken), userID, encryptedToken, now); err != nil || tx.Commit() != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not complete registration"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_registered", fmt.Sprintf("user_id=%d username=%s", userID, d.Username))
	s.broadcast("audit")
	reply(w, http.StatusCreated, map[string]any{"status": "created", "username": d.Username, "network_token": networkToken})
}

// accountLogin verifies credentials and starts an authenticated web session.
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

func (s *server) issueAccountToken(userID int64) (string, error) {
	var encrypted []byte
	if err := s.db.QueryRow("SELECT encrypted_token FROM account_tokens WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1", userID).Scan(&encrypted); err == nil && len(encrypted) > 0 {
		if token, decryptErr := s.decryptAccountToken(encrypted); decryptErr == nil && token != "" {
			return token, nil
		}
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	encrypted, err = s.encryptAccountToken(token)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec("INSERT INTO account_tokens(token_hash,user_id,encrypted_token,created_at) VALUES(?,?,?,?)", tokenDigest(token), userID, encrypted, time.Now().Unix())
	if err != nil {
		return "", err
	}
	return token, nil
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
	encryptedToken, err := s.encryptAccountToken(token)
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not protect account token"})
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
		_, err = tx.Exec("INSERT INTO account_tokens(token_hash,user_id,encrypted_token,created_at) VALUES(?,?,?,?)", tokenDigest(token), userID, encryptedToken, now)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": "could not rotate account token"})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "account_token_rotated", fmt.Sprintf("user_id=%d", userID))
	s.broadcast("audit")
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
	if provided == "" || s.db == nil || s.accountTokenUserStmt == nil {
		return 0, false
	}
	var userID int64
	err := s.accountTokenUserStmt.QueryRow(tokenDigest(provided)).Scan(&userID)
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
	if !s.networkTokenValid(r) && !s.anyNodeTokenValid(r) && !s.inviteRegistrationAuthorized(r) {
		reply(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

func (s *server) inviteRegistrationAuthorized(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/register" {
		return false
	}
	token := r.Header.Get("X-Mesh-Invite")
	if token == "" {
		return false
	}
	// A 6-character code is only brute-force resistant while attempts are
	// bounded. The WebSocket upgrade applies the same per-IP limit; this
	// covers the legacy HTTP registration path as well. The bucket is kept
	// separate so enrollment retries cannot lock out the handshake quota.
	if !s.allowInviteAttempt(r.RemoteAddr) {
		return false
	}
	var used sql.NullInt64
	if err := s.db.QueryRow("SELECT used_at FROM invites WHERE token=?", token).Scan(&used); err != nil || !used.Valid {
		return false
	}
	// A consumed invite must only authorize the follow-up registration of the
	// node that just enrolled over the WebSocket. Accepting it forever turned
	// every historical invite into a permanent (and brute-forceable)
	// registration credential.
	return time.Since(time.Unix(used.Int64, 0)) <= inviteEnrollmentWindow
}

func (s *server) networkTokenValid(r *http.Request) bool {
	provided := r.Header.Get("X-Mesh-Token")
	if len(provided) != 0 && len(provided) == len(s.token) && subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1 {
		return true
	}
	_, ok := s.accountTokenUser(r)
	return ok
}

// anyNodeTokenValid matches the credential against per-node enrollment
// tokens. Unlike the network token or account tokens, a node token carries no
// admin API privileges: it only satisfies the node-facing auth checks, and it
// is revoked together with the node it was issued for.
func (s *server) anyNodeTokenValid(r *http.Request) bool {
	provided := r.Header.Get("X-Mesh-Token")
	if provided == "" || s.db == nil {
		return false
	}
	var one int
	return s.db.QueryRow("SELECT 1 FROM node_tokens WHERE token_hash=? AND revoked_at IS NULL", tokenDigest(provided)).Scan(&one) == nil
}

// issueNodeToken mints the per-node enrollment credential handed out in the
// register response under the legacy "network_token" field name (old clients
// store and use whatever opaque token they receive).
func (s *server) issueNodeToken(nodeID string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`INSERT INTO node_tokens(node_id,token_hash,created_at) VALUES(?,?,?) ON CONFLICT(node_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=excluded.created_at,revoked_at=NULL`, nodeID, tokenDigest(token), time.Now().Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

// nodeRevoked reports whether a node identity is banned. Revocation is keyed
// by the persistent node_id (derived from the node's private key), so a
// removed node cannot return by re-registering with the same identity.
func (s *server) nodeRevoked(nodeID string) bool {
	var one int
	return s.db.QueryRow("SELECT 1 FROM revoked_nodes WHERE node_id=?", nodeID).Scan(&one) == nil
}
