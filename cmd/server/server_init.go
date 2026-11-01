package main

import (
	"os"

	_ "modernc.org/sqlite"
)

func value(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// init opens the database, applies schema setup, and loads server settings.
func (s *server) init() error {
	_, err := s.db.Exec(`PRAGMA foreign_keys = ON; CREATE TABLE IF NOT EXISTS nodes (node_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,nat_type TEXT NOT NULL,role TEXT NOT NULL,endpoint TEXT NOT NULL,requested_role TEXT NOT NULL DEFAULT 'auto',relay_capable INTEGER NOT NULL DEFAULT 1,capacity INTEGER NOT NULL DEFAULT 1,last_seen INTEGER NOT NULL,created_at INTEGER NOT NULL,mesh_ip TEXT,owner_id INTEGER REFERENCES users(id));CREATE TABLE IF NOT EXISTS services (node_id TEXT NOT NULL,name TEXT NOT NULL,target_host TEXT NOT NULL,target_port INTEGER NOT NULL,allowed_nodes TEXT NOT NULL DEFAULT '*',PRIMARY KEY(node_id,name));CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS dns_settings (key TEXT PRIMARY KEY,value TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS invites (token TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER,owner_id INTEGER REFERENCES users(id));CREATE TABLE IF NOT EXISTS audit_log (created_at INTEGER NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL);CREATE TABLE IF NOT EXISTS graph_links (a TEXT NOT NULL,b TEXT NOT NULL,cost REAL NOT NULL DEFAULT 1,PRIMARY KEY(a,b));CREATE TABLE IF NOT EXISTS role_overrides (node_id TEXT PRIMARY KEY,role TEXT NOT NULL);CREATE TABLE IF NOT EXISTS node_network (node_id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',routes TEXT NOT NULL DEFAULT '[]',dns_ip TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS dns_records(node_id TEXT NOT NULL,name TEXT NOT NULL UNIQUE,lan_ip TEXT NOT NULL,PRIMARY KEY(node_id,name));CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL COLLATE NOCASE UNIQUE,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL,last_login_at INTEGER,disabled INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS account_tokens (token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,encrypted_token BLOB,created_at INTEGER NOT NULL,revoked_at INTEGER);CREATE INDEX IF NOT EXISTS account_tokens_user_idx ON account_tokens(user_id);CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY,csrf_hash TEXT NOT NULL,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER);CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id);CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);CREATE TABLE IF NOT EXISTS account_invites (token_hash TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER);CREATE TABLE IF NOT EXISTS server_secrets (name TEXT PRIMARY KEY,value BLOB NOT NULL);CREATE TABLE IF NOT EXISTS update_settings (arch TEXT PRIMARY KEY,url TEXT NOT NULL DEFAULT '');CREATE TABLE IF NOT EXISTS update_binaries (arch TEXT PRIMARY KEY,data BLOB NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,updated_at INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS node_firewall (node_id TEXT PRIMARY KEY,mode TEXT NOT NULL DEFAULT 'allow_all',ports TEXT NOT NULL DEFAULT '[]',updated_at INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS node_tokens (node_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,created_at INTEGER NOT NULL,revoked_at INTEGER);CREATE TABLE IF NOT EXISTS revoked_nodes (node_id TEXT PRIMARY KEY,reason TEXT NOT NULL DEFAULT '',revoked_at INTEGER NOT NULL);`)
	if err != nil {
		return err
	}
	if _, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS graph_blocks (a TEXT NOT NULL,b TEXT NOT NULL,PRIMARY KEY(a,b))`); err != nil {
		return err
	}
	if _, err = s.db.Exec(`CREATE TABLE IF NOT EXISTS port_forwards (id INTEGER PRIMARY KEY AUTOINCREMENT,source_node_id TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,listen_host TEXT NOT NULL,listen_port INTEGER NOT NULL,target_node_id TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,target_host TEXT NOT NULL,target_port INTEGER NOT NULL,UNIQUE(source_node_id,listen_host,listen_port))`); err != nil {
		return err
	}
	rows, err := s.db.Query("PRAGMA table_info(nodes)")
	if err != nil {
		return err
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull int
		var defaultValue any
		var primaryKey int
		if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	// Migration statements below must run after the schema cursor releases the
	// sole connection from the pool.
	if err = rows.Close(); err != nil {
		return err
	}
	if !columns["mesh_ip"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN mesh_ip TEXT"); err != nil {
			return err
		}
	}
	if !columns["owner_id"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN owner_id INTEGER"); err != nil {
			return err
		}
	}
	inviteColumns := map[string]bool{}
	inviteRows, queryErr := s.db.Query("PRAGMA table_info(invites)")
	if queryErr != nil {
		return queryErr
	}
	for inviteRows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if queryErr = inviteRows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); queryErr != nil {
			inviteRows.Close()
			return queryErr
		}
		inviteColumns[name] = true
	}
	if queryErr = inviteRows.Close(); queryErr != nil {
		return queryErr
	}
	if !inviteColumns["owner_id"] {
		if _, err = s.db.Exec("ALTER TABLE invites ADD COLUMN owner_id INTEGER"); err != nil {
			return err
		}
	}
	accountTokenColumns := map[string]bool{}
	tokenRows, queryErr := s.db.Query("PRAGMA table_info(account_tokens)")
	if queryErr != nil {
		return queryErr
	}
	for tokenRows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if queryErr = tokenRows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); queryErr != nil {
			tokenRows.Close()
			return queryErr
		}
		accountTokenColumns[name] = true
	}
	if queryErr = tokenRows.Close(); queryErr != nil {
		return queryErr
	}
	if !accountTokenColumns["encrypted_token"] {
		if _, err = s.db.Exec("ALTER TABLE account_tokens ADD COLUMN encrypted_token BLOB"); err != nil {
			return err
		}
	}
	if err = s.loadTokenKey(); err != nil {
		return err
	}
	if !columns["requested_role"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN requested_role TEXT"); err != nil {
			return err
		}
		if _, err = s.db.Exec("UPDATE nodes SET requested_role = CASE WHEN role = 'superpeer' THEN 'superpeer' ELSE 'auto' END"); err != nil {
			return err
		}
	}
	if !columns["relay_capable"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN relay_capable INTEGER NOT NULL DEFAULT 1"); err != nil {
			return err
		}
	}
	if !columns["connected_at"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN connected_at INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
		if _, err = s.db.Exec("UPDATE nodes SET connected_at=last_seen WHERE connected_at=0"); err != nil {
			return err
		}
	}
	if !columns["goarch"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN goarch TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}
	if !columns["lan_addrs"] {
		if _, err = s.db.Exec("ALTER TABLE nodes ADD COLUMN lan_addrs TEXT NOT NULL DEFAULT '[]'"); err != nil {
			return err
		}
	}
	if err = s.loadSettings(); err != nil {
		return err
	}
	return s.prepareRegisterStatements()
}

// Registration is the heartbeat hot path. Keeping these statements prepared
// avoids reparsing the same SQLite SQL for every connected node every 15s.
func (s *server) prepareRegisterStatements() error {
	accountTokenUser, err := s.db.Prepare(`SELECT t.user_id FROM account_tokens t JOIN users u ON u.id=t.user_id
		WHERE t.token_hash=? AND t.revoked_at IS NULL AND u.disabled=0`)
	if err != nil {
		return err
	}
	lookup, err := s.db.Prepare(`SELECT n.node_id,n.public_key,n.nat_type,n.role,n.endpoint,n.requested_role,n.relay_capable,n.capacity,n.last_seen,n.created_at,n.connected_at,n.mesh_ip,n.goarch,n.owner_id,o.role
		FROM nodes n LEFT JOIN role_overrides o ON o.node_id=n.node_id WHERE n.node_id=?`)
	if err != nil {
		accountTokenUser.Close()
		return err
	}
	insert, err := s.db.Prepare(`INSERT INTO nodes(node_id,public_key,nat_type,role,endpoint,requested_role,relay_capable,capacity,last_seen,created_at,connected_at,mesh_ip,goarch,lan_addrs,owner_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		accountTokenUser.Close()
		lookup.Close()
		return err
	}
	update, err := s.db.Prepare(`UPDATE nodes SET public_key=?,nat_type=?,role=?,endpoint=?,requested_role=?,relay_capable=?,capacity=?,last_seen=?,connected_at=CASE WHEN last_seen < ? THEN ? ELSE connected_at END,mesh_ip=?,goarch=COALESCE(NULLIF(?,''),goarch),lan_addrs=?,owner_id=COALESCE(owner_id,?) WHERE node_id=?`)
	if err != nil {
		accountTokenUser.Close()
		lookup.Close()
		insert.Close()
		return err
	}
	s.accountTokenUserStmt = accountTokenUser
	s.registerLookupStmt = lookup
	s.registerInsertStmt = insert
	s.registerUpdateStmt = update
	return nil
}
