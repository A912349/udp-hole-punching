package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"home-udp-mesh/internal/autostart"

	"golang.org/x/net/websocket"
	_ "modernc.org/sqlite"
)

func envInt(name string, fallback int) int {
	if v, e := strconv.Atoi(os.Getenv(name)); e == nil && v > 0 {
		return v
	}
	return fallback
}

func main() {
	pprofListen := flag.String("pprof-listen", "", "local pprof listener, e.g. 127.0.0.1:6061")
	if len(os.Args) > 1 && (os.Args[1] == "--add-autostart" || os.Args[1] == "--del-autostart") {
		var err error
		if os.Args[1] == "--add-autostart" {
			err = autostart.Install("mesh-server", os.Args[2:], os.Environ())
		} else {
			err = autostart.Remove("mesh-server")
		}
		if err != nil {
			log.Fatal(err)
		}
		log.Println("autostart updated")
		return
	}
	flag.Parse()
	if *pprofListen != "" {
		host, _, err := net.SplitHostPort(*pprofListen)
		if err != nil {
			log.Fatalf("invalid --pprof-listen: %v", err)
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			log.Fatal("--pprof-listen must use localhost or a loopback IP")
		}
		go func() {
			log.Printf("[SERVER] pprof available at http://%s/debug/pprof/", *pprofListen)
			if err := http.ListenAndServe(*pprofListen, nil); err != nil {
				log.Printf("[SERVER] pprof listener stopped: %v", err)
			}
		}()
	}
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
		sessions:            map[string]map[string]*rendezvousPeer{},
		controls:            map[*controlClient]string{},
		symmetricRendezvous: map[string]symmetricRendezvous{},
		metrics:             map[string]linkMetric{},
		linkCache:           map[string]cachedLinks{},
		updateResults:       map[string]updateResult{},
		inviteAttempts:      map[string][]time.Time{},
		accountAttempts:     map[string][]time.Time{},
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
	// Audit retention: the log grows on every login, update and role change,
	// so old rows are pruned in the background. MESH_AUDIT_RETENTION_DAYS=0
	// disables pruning entirely. Defaults to 90 days.
	if retentionDays := envInt("MESH_AUDIT_RETENTION_DAYS", 90); retentionDays > 0 {
		go func(days int) {
			prune := func() {
				if _, err := s.db.Exec("DELETE FROM audit_log WHERE created_at < ?", time.Now().Unix()-int64(days)*86400); err != nil {
					log.Printf("[SERVER] audit retention: %v", err)
				}
			}
			prune()
			for range time.Tick(6 * time.Hour) {
				prune()
			}
		}(retentionDays)
	}
	// Graph maintenance: a superpeer that silently goes offline only frees
	// its slot when something triggers rebalanceRoles (usually the next
	// registration). Run it periodically so a replacement is promoted and
	// offline nodes drop out of the graph without waiting for any event, and
	// connected clients receive the healed topology right away.
	go func() {
		for {
			ttl := s.settings().TTL
			interval := time.Duration(ttl) * time.Second / 2
			if interval < 10*time.Second {
				interval = 10 * time.Second
			}
			if interval > 60*time.Second {
				interval = 60 * time.Second
			}
			time.Sleep(interval)
			changed, err := s.rebalanceRoles()
			if err != nil {
				log.Printf("[SERVER] topology maintenance: %v", err)
				continue
			}
			if changed {
				s.invalidateLinkCache()
				s.pushTopologies()
				s.broadcast("topology", "audit")
				log.Printf("[SERVER] topology maintenance: roles rebalanced after membership change")
			}
		}
	}()
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
			if !s.networkTokenValid(r) && !s.anyNodeTokenValid(r) {
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
	mux.HandleFunc("GET /v1/admin/stream", s.adminStream)
	mux.HandleFunc("GET /v1/admin/invites", s.adminInvite)
	mux.HandleFunc("POST /v1/admin/invites", s.adminInvite)
	mux.HandleFunc("DELETE /v1/admin/nodes/{node_id}", s.adminNode)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/role", s.adminNodeRole)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/network", s.adminNodeNetwork)
	mux.HandleFunc("GET /v1/admin/nodes/{node_id}/firewall", s.adminFirewallGet)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/firewall", s.adminFirewallSet)
	mux.HandleFunc("GET /v1/admin/revoked", s.adminRevoked)
	mux.HandleFunc("DELETE /v1/admin/revoked/{node_id}", s.adminUnban)
	mux.HandleFunc("POST /v1/admin/nodes/{node_id}/network/routes", s.adminAddNodeRoute)
	mux.HandleFunc("DELETE /v1/admin/nodes/{node_id}/network/routes", s.adminRemoveNodeRoute)
	mux.HandleFunc("GET /v1/admin/graph", s.adminGraph)
	mux.HandleFunc("PUT /v1/admin/graph", s.adminGraph)
	mux.HandleFunc("GET /v1/admin/forwards", s.adminForwards)
	mux.HandleFunc("POST /v1/admin/forwards", s.adminForwards)
	mux.HandleFunc("DELETE /v1/admin/forwards/{id}", s.adminForward)
	mux.HandleFunc("GET /v1/admin/updates", s.adminUpdates)
	mux.HandleFunc("PUT /v1/admin/updates", s.adminUpdates)
	mux.HandleFunc("POST /v1/admin/updates/dispatch", s.adminUpdateDispatch)
	mux.HandleFunc("PUT /v1/admin/updates/binaries/{arch}", s.adminUpdateBinary)
	mux.HandleFunc("DELETE /v1/admin/updates/binaries/{arch}", s.adminUpdateBinary)
	mux.HandleFunc("GET /v1/update/binaries/{arch}", s.nodeUpdateBinary)
	// Legacy endpoints intentionally stay unauthenticated: the experimental
	// punch client predates the mesh network token and can use this coordinator.
	mux.HandleFunc("POST /register", s.rendezvousRegister)
	mux.HandleFunc("GET /wait", s.rendezvousWait)
	port := value("MESH_PORT", "8001")
	log.Printf("[SERVER] starting on 0.0.0.0:%s", port)
	server := &http.Server{
		Addr: ":" + port, Handler: gzipAdmin(securityHeaders(mux)),
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
