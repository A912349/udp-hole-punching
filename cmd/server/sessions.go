package main

import (
	"crypto/subtle"
	"database/sql"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	_ "modernc.org/sqlite"
)

func requestHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
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