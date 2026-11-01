package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func validGoArch(v string) bool {
	if v == "" {
		return true
	}
	if len(v) > 32 {
		return false
	}
	goos, goarch, ok := strings.Cut(v, "/")
	if !ok || goos == "" || goarch == "" {
		return false
	}
	return isLowerAlnum(goos) && isLowerAlnum(goarch)
}

func isLowerAlnum(v string) bool {
	for _, r := range v {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (s *server) updateURLs() map[string]string {
	urls := map[string]string{}
	rows, err := s.db.Query("SELECT arch,url FROM update_settings")
	if err != nil {
		return urls
	}
	defer rows.Close()
	for rows.Next() {
		var arch, raw string
		if rows.Scan(&arch, &raw) == nil && strings.TrimSpace(raw) != "" {
			urls[arch] = strings.TrimSpace(raw)
		}
	}
	return urls
}

func (s *server) updateBinaries() []updateBinaryInfo {
	list := []updateBinaryInfo{}
	rows, err := s.db.Query("SELECT arch,sha256,size,updated_at FROM update_binaries")
	if err != nil {
		return list
	}
	defer rows.Close()
	for rows.Next() {
		var b updateBinaryInfo
		if rows.Scan(&b.Arch, &b.SHA256, &b.Size, &b.UpdatedAt) == nil {
			// %2F keeps "linux/arm64" inside one wildcard segment; the mux
			// decodes it back in the handler.
			b.Path = "/v1/update/binaries/" + url.PathEscape(b.Arch)
			list = append(list, b)
		}
	}
	return list
}

// buildUpdateSources collects everything an update command can reference.
// Uploaded binaries take precedence on the node; links are the fallback.
func (s *server) buildUpdateSources() updateSources {
	sources := updateSources{Binaries: map[string]updateBinaryInfo{}, URLs: map[string]string{}}
	for arch, u := range s.updateURLs() {
		sources.URLs[arch] = u
	}
	for _, b := range s.updateBinaries() {
		sources.Binaries[b.Arch] = b
	}
	return sources
}

// adminUpdates serves the update configuration. GET returns the configured
// links, stored binaries and last per-node update reports; PUT replaces the
// link set. Binary payloads are managed by adminUpdateBinary.
func (s *server) adminUpdates(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		reply(w, http.StatusOK, map[string]any{"urls": s.updateURLs(), "binaries": s.updateBinaries(), "results": s.updateStatusSnapshot()})
		return
	}
	var next struct {
		URLs map[string]string `json:"urls"`
	}
	if err := decodeJSON(w, r, &next); err != nil || next.URLs == nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"urls\": {\"goos/goarch\": \"https://...\"}}"})
		return
	}
	for arch, raw := range next.URLs {
		if arch == "" || !validGoArch(arch) {
			reply(w, http.StatusBadRequest, map[string]string{"error": "invalid architecture key " + arch})
			return
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > 512 {
			reply(w, http.StatusBadRequest, map[string]string{"error": "invalid download link for " + arch})
			return
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if _, err = tx.Exec("DELETE FROM update_settings"); err != nil {
		_ = tx.Rollback()
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for arch, raw := range next.URLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, err = tx.Exec("INSERT INTO update_settings(arch,url) VALUES(?,?)", arch, raw); err != nil {
			_ = tx.Rollback()
			reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if err = tx.Commit(); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "update_links_saved", fmt.Sprintf("archs=%d", len(next.URLs)))
	s.broadcast("updates", "audit")
	reply(w, http.StatusOK, map[string]any{"urls": s.updateURLs()})
}

// adminUpdateBinary stores or removes one architecture binary on the
// coordinator. Uploads are raw bodies (application/octet-stream); the node
// later downloads from /v1/update/binaries/{arch} with its network token.
func (s *server) adminUpdateBinary(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	arch := r.PathValue("arch")
	if arch == "" || !validGoArch(arch) {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid architecture"})
		return
	}
	if r.Method == http.MethodDelete {
		if _, err := s.db.Exec("DELETE FROM update_binaries WHERE arch=?", arch); err != nil {
			reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "update_binary_removed", arch)
		s.broadcast("updates", "audit")
		reply(w, http.StatusOK, map[string]string{"status": "removed"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, updateMaxBinaryBytes))
	if err != nil {
		reply(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "binary too large or unreadable"})
		return
	}
	if len(body) < 1024 {
		reply(w, http.StatusBadRequest, map[string]string{"error": "file is too small to be a mesh-node binary"})
		return
	}
	sum := sha256.Sum256(body)
	_, err = s.db.Exec(`INSERT INTO update_binaries(arch,data,sha256,size,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(arch) DO UPDATE SET data=excluded.data,sha256=excluded.sha256,size=excluded.size,updated_at=excluded.updated_at`,
		arch, body, hex.EncodeToString(sum[:]), len(body), time.Now().Unix())
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.db.Exec("INSERT INTO audit_log(created_at,event,detail) VALUES(?,?,?)", time.Now().Unix(), "update_binary_stored", fmt.Sprintf("%s size=%d", arch, len(body)))
	s.broadcast("updates", "audit")
	reply(w, http.StatusOK, map[string]any{"arch": arch, "size": len(body), "sha256": hex.EncodeToString(sum[:])})
}

// nodeUpdateBinary serves a stored client binary to an authenticated node.
func (s *server) nodeUpdateBinary(w http.ResponseWriter, r *http.Request) {
	if !s.auth(w, r) {
		return
	}
	arch := r.PathValue("arch")
	if arch == "" || !validGoArch(arch) {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid architecture"})
		return
	}
	var data []byte
	err := s.db.QueryRow("SELECT data FROM update_binaries WHERE arch=?", arch).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		reply(w, http.StatusNotFound, map[string]string{"error": "no stored binary for " + arch})
		return
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (s *server) connectedNodeIDs() []string {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range s.controls {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (s *server) nodeArch(nodeID string) string {
	var arch string
	_ = s.db.QueryRow("SELECT goarch FROM nodes WHERE node_id=?", nodeID).Scan(&arch)
	return arch
}

// adminUpdateDispatch pushes the "update" control event to one node or to
// every connected node. Nodes whose architecture has no configured source are
// reported back instead of receiving a command they cannot act on.
