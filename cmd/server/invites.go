package main

import (
	"crypto/rand"
	"database/sql"
	"net"
	"net/http"
	"time"
)

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
func (s *server) allowInviteAttempt(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	now := time.Now()
	cutoff := now.Add(-30 * time.Second)
	s.inviteMu.Lock()
	defer s.inviteMu.Unlock()
	if s.inviteAttempts == nil {
		s.inviteAttempts = map[string][]time.Time{}
	}
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
	accountID, scoped := s.accountIDForRequest(r)
	if r.Method == http.MethodGet {
		query := "SELECT token,created_at,expires_at,used_at FROM invites WHERE expires_at>=?"
		args := []any{time.Now().Unix()}
		if scoped {
			query += " AND owner_id=?"
			args = append(args, accountID)
		}
		query += " ORDER BY created_at DESC"
		rows, err := s.db.Query(query, args...)
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
	var ownerValue any
	if scoped {
		ownerValue = accountID
	}
	if _, err := s.db.Exec("INSERT INTO invites(token,created_at,expires_at,owner_id) VALUES(?,?,?,?)", token, now, now+60, ownerValue); err != nil {
		reply(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", now, "invite_created", "six-digit device invite created")
	s.broadcast("audit")
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": now + 60, "expires_in_seconds": 60})
}
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
	s.broadcast("audit")
	// The raw token is returned exactly once and is never logged or stored.
	reply(w, http.StatusCreated, map[string]any{"invite_token": token, "expires_at": expires, "expires_in_seconds": 24 * 60 * 60})
}
