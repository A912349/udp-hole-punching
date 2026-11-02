package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

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
	s.broadcast("topology", "audit")
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
	s.broadcast("topology", "audit")
	s.pushTopologies()
	reply(w, 200, map[string]any{"removed": lan, "routes": remaining})
}
