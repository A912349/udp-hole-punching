package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"time"
	_ "modernc.org/sqlite"
)

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

func (s *server) networkTokenValid(r *http.Request) bool {
	provided := r.Header.Get("X-Mesh-Token")
	if len(provided) != 0 && len(provided) == len(s.token) && subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1 {
		return true
	}
	_, ok := s.accountTokenUser(r)
	return ok
}

func (s *server) anyNodeTokenValid(r *http.Request) bool {
	provided := r.Header.Get("X-Mesh-Token")
	if provided == "" || s.db == nil {
		return false
	}
	var one int
	return s.db.QueryRow("SELECT 1 FROM node_tokens WHERE token_hash=? AND revoked_at IS NULL", tokenDigest(provided)).Scan(&one) == nil
}

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

func (s *server) nodeRevoked(nodeID string) bool {
	var one int
	return s.db.QueryRow("SELECT 1 FROM revoked_nodes WHERE node_id=?", nodeID).Scan(&one) == nil
}