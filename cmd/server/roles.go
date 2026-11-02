package main

import (
	"sort"
	"time"
)

func (s *server) rebalanceRoles() (bool, error) {
	return s.rebalanceRolesFor(nil)
}
func (s *server) rebalanceRolesFor(ownerID *int64) (bool, error) {
	c := s.settings()
	query := "SELECT node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs FROM nodes WHERE last_seen>=?"
	args := []any{time.Now().Unix() - int64(c.TTL)}
	if ownerID != nil {
		query += " AND owner_id=?"
		args = append(args, *ownerID)
	}
	nodes, err := s.rows(query, args...)
	if err != nil {
		return false, err
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
	changed := false
	for _, n := range nodes {
		role := "client"
		if super[n.ID] {
			role = "superpeer"
		}
		if n.Role == role {
			continue
		}
		if _, err := s.db.Exec("UPDATE nodes SET role=? WHERE node_id=?", role, n.ID); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}
