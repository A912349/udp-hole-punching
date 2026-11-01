package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

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
	TTL            int    `json:"node_ttl_seconds"`
	AutoSuperpeers int    `json:"auto_superpeers"`
	BackboneDegree int    `json:"backbone_degree"`
	ClientLinks    int    `json:"client_links"`
	SymmetricLinks int    `json:"symmetric_links"`
	DNSUpstream    string `json:"dns_upstream"`
}

func (s *server) settings() topologySettings {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return topologySettings{TTL: int(s.ttl), AutoSuperpeers: s.auto, BackboneDegree: s.backboneDegree, ClientLinks: s.clientLinks, SymmetricLinks: s.symmetricLinks, DNSUpstream: s.dnsUpstream}
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
	var dnsValue string
	if err := s.db.QueryRow("SELECT value FROM dns_settings WHERE key='upstream'").Scan(&dnsValue); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	settings.DNSUpstream = dnsValue
	if err := validSettings(settings); err != nil {
		return fmt.Errorf("stored topology settings: %w", err)
	}
	s.configMu.Lock()
	s.ttl = int64(settings.TTL)
	s.auto = settings.AutoSuperpeers
	s.backboneDegree = settings.BackboneDegree
	s.clientLinks = settings.ClientLinks
	s.symmetricLinks = settings.SymmetricLinks
	s.dnsUpstream = settings.DNSUpstream
	s.configMu.Unlock()
	return nil
}

func normalizeDNSUpstream(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	if h, port, err := net.SplitHostPort(v); err == nil {
		p, e := strconv.Atoi(port)
		if h == "" || e != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid dns address")
		}
		return net.JoinHostPort(h, strconv.Itoa(p)), nil
	}
	if ip := net.ParseIP(v); ip != nil {
		return net.JoinHostPort(v, "53"), nil
	}
	if strings.ContainsAny(v, " /\\") {
		return "", fmt.Errorf("invalid dns address")
	}
	return net.JoinHostPort(v, "53"), nil
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
	var err error
	next.DNSUpstream, err = normalizeDNSUpstream(next.DNSUpstream)
	if err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_, err = s.db.Exec(`INSERT INTO settings(key,value) VALUES('node_ttl_seconds',?),('auto_superpeers',?),('backbone_degree',?),('client_links',?),('symmetric_links',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next.TTL, next.AutoSuperpeers, next.BackboneDegree, next.ClientLinks, next.SymmetricLinks)
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
	s.dnsUpstream = next.DNSUpstream
	s.configMu.Unlock()
	s.invalidateLinkCache()
	if _, err := s.rebalanceRoles(); err != nil {
		reply(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.db.Exec(`INSERT INTO dns_settings(key,value) VALUES('upstream',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, next.DNSUpstream)
	s.pushTopologies()
	s.broadcast("config", "audit")
	reply(w, http.StatusOK, next)
}

// validGoArch accepts an empty value (old clients) or a "goos/goarch" pair
// such as "linux/mipsle". The charset matches what the Go runtime reports.
