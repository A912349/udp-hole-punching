package main

import "net/http"

// Bootstrap requests on the control WebSocket can supply the version they
// already applied. Keep status 200 and the same topology_version field: the
// node's existing unchanged-version path preserves its current view and still
// resynchronizes OS routes. Old clients omit the condition and get full data.
func bootstrapUnchanged(w http.ResponseWriter, r *http.Request, version string) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return false
	}
	var condition struct {
		Version string `json:"version"`
	}
	if err := decodeJSON(w, r, &condition); err != nil {
		reply(w, http.StatusBadRequest, map[string]string{"error": "invalid bootstrap condition"})
		return true
	}
	if condition.Version == "" || condition.Version != version {
		return false
	}
	reply(w, http.StatusOK, map[string]any{"topology_version": version, "unchanged": true})
	return true
}
