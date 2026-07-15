"""Control-plane server for the two-tier home-service mesh.

The server stores node metadata and distributes a static topology.  It never
receives or forwards overlay DATA packets.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import sqlite3
import time
from contextlib import closing

from flask import Flask, jsonify, request

from mesh_protocol import b64decode, node_id as public_key_node_id


DATABASE_PATH = os.environ.get("MESH_DATABASE", "mesh.db")
NETWORK_TOKEN = os.environ.get("MESH_NETWORK_TOKEN")
MAX_SUPERPEER_DEGREE = 6
CLIENT_SUPERPEERS = 3
AUTO_SUPERPEERS = max(1, int(os.environ.get("MESH_AUTO_SUPERPEERS", "2")))
NODE_TTL_SECONDS = int(os.environ.get("MESH_NODE_TTL_SECONDS", "45"))
MESH_IP_NETWORK = ipaddress.IPv4Network(os.environ.get("MESH_IP_NETWORK", "10.77.0.0/24"))

app = Flask(__name__)


def db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with closing(db()) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                nat_type TEXT NOT NULL,
                role TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                requested_role TEXT NOT NULL DEFAULT 'auto',
                relay_capable INTEGER NOT NULL DEFAULT 1,
                capacity INTEGER NOT NULL DEFAULT 1,
                last_seen INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS services (
                node_id TEXT NOT NULL,
                name TEXT NOT NULL,
                target_host TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                allowed_nodes TEXT NOT NULL DEFAULT '*',
                PRIMARY KEY (node_id, name),
                FOREIGN KEY (node_id) REFERENCES nodes(node_id)
            );
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(nodes)")}
        if "mesh_ip" not in columns:
            connection.execute("ALTER TABLE nodes ADD COLUMN mesh_ip TEXT")
        if "requested_role" not in columns:
            connection.execute("ALTER TABLE nodes ADD COLUMN requested_role TEXT")
            connection.execute(
                "UPDATE nodes SET requested_role = CASE WHEN role = 'superpeer' THEN 'superpeer' ELSE 'auto' END"
            )
        if "relay_capable" not in columns:
            connection.execute("ALTER TABLE nodes ADD COLUMN relay_capable INTEGER NOT NULL DEFAULT 1")
        connection.commit()


def require_token():
    if not NETWORK_TOKEN:
        return None
    if request.headers.get("X-Mesh-Token") != NETWORK_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    return None


def log(message: str):
    print(f"[SERVER] {message}")


def topology_version(rows) -> str:
    source = "|".join(
        f"{row['node_id']}:{row['public_key']}:{row['nat_type']}:{row['role']}:"
        f"{row['endpoint']}:{row['mesh_ip']}:{row['capacity']}" for row in rows
    )
    return hashlib.sha256(source.encode()).hexdigest()[:16]


def row_to_node(row):
    return {
        "node_id": row["node_id"], "public_key": row["public_key"],
        "nat_type": row["nat_type"], "role": row["role"], "endpoint": row["endpoint"],
        "capacity": row["capacity"], "mesh_ip": row["mesh_ip"],
    }


def allocate_mesh_ip(connection: sqlite3.Connection) -> str:
    """Allocate a persistent DHCP-like mesh address, reserving the first host."""
    assigned = {row[0] for row in connection.execute("SELECT mesh_ip FROM nodes WHERE mesh_ip IS NOT NULL")}
    for candidate in list(MESH_IP_NETWORK.hosts())[1:]:
        address = str(candidate)
        if address not in assigned:
            return address
    raise RuntimeError("mesh address pool is exhausted")


def assign_role(
    connection: sqlite3.Connection,
    node_id: str,
    requested_role: str,
    nat_type: str,
    relay_capable: bool,
    capacity: int,
    now: int,
) -> str:
    """Keep manual roles fixed and elect stable cone nodes for auto relays."""
    if requested_role == "superpeer":
        return "superpeer"
    if requested_role == "client" or nat_type != "cone" or not relay_capable:
        return "client"

    cutoff = now - NODE_TTL_SECONDS
    rows = connection.execute(
        """SELECT node_id, nat_type, requested_role, relay_capable, capacity, created_at
           FROM nodes WHERE last_seen >= ? AND node_id != ?""",
        (cutoff, node_id),
    ).fetchall()
    manual_relays = [row for row in rows if row["requested_role"] == "superpeer"]
    slots = max(0, AUTO_SUPERPEERS - len(manual_relays))
    if slots == 0:
        return "client"

    existing = connection.execute("SELECT created_at FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
    candidates = [
        row for row in rows
        if row["requested_role"] == "auto" and row["nat_type"] == "cone" and row["relay_capable"]
    ]
    candidates.append({
        "node_id": node_id,
        "capacity": capacity,
        "created_at": existing["created_at"] if existing else now,
    })
    candidates.sort(key=lambda row: (-int(row["capacity"]), int(row["created_at"]), row["node_id"]))
    elected = {row["node_id"] for row in candidates[:slots]}
    return "superpeer" if node_id in elected else "client"


def backbone_links(superpeers):
    """Deterministic near-full mesh; replaceable by future graph optimizer."""
    ids = [row["node_id"] for row in superpeers]
    if len(ids) < 2:
        return []
    degree = min(MAX_SUPERPEER_DEGREE, len(ids) - 1)
    links = set()
    for index, source in enumerate(ids):
        for step in range(1, degree // 2 + 1):
            target = ids[(index + step) % len(ids)]
            links.add(tuple(sorted((source, target))))
        if degree % 2 and len(ids) % 2 == 0:
            links.add(tuple(sorted((source, ids[(index + len(ids) // 2) % len(ids)]))))
    return [{"a": left, "b": right, "cost": 1.0} for left, right in sorted(links)]


def access_links(nodes, superpeers):
    """Spread clients across relays while retaining primary and backup paths."""
    links = []
    assigned = {row["node_id"]: 0 for row in superpeers}
    for row in sorted(nodes, key=lambda item: item["node_id"]):
        if row["role"] != "client":
            continue
        ranked = sorted(
            superpeers,
            key=lambda relay: (
                assigned[relay["node_id"]] / max(1, relay["capacity"]),
                -relay["capacity"],
                relay["node_id"],
            ),
        )
        for index, superpeer in enumerate(ranked[:CLIENT_SUPERPEERS]):
            assigned[superpeer["node_id"]] += 1
            links.append({
                "a": row["node_id"], "b": superpeer["node_id"],
                "cost": 1.0 + index * 0.1,
            })
    return links


@app.post("/v1/register")
def register():
    if response := require_token():
        return response
    data = request.get_json(silent=True) or {}
    required = ("node_id", "public_key", "nat_type", "role", "endpoint")
    if any(not data.get(field) for field in required):
        return jsonify({"error": "missing required fields"}), 400
    if data["nat_type"] not in {"cone", "symmetric"}:
        return jsonify({"error": "invalid nat_type"}), 400
    if data["role"] not in {"auto", "superpeer", "client"}:
        return jsonify({"error": "invalid role"}), 400
    if data["role"] == "superpeer" and data["nat_type"] != "cone":
        log(f"register rejected node={data.get('node_id')} reason=superpeer requires cone")
        return jsonify({"error": "only cone nodes may be superpeers"}), 400
    requested_mesh_ip = data.get("mesh_ip")
    if requested_mesh_ip:
        try:
            requested_mesh_ip = str(ipaddress.IPv4Address(requested_mesh_ip))
        except ipaddress.AddressValueError:
            return jsonify({"error": "invalid mesh_ip"}), 400
    try:
        if public_key_node_id(b64decode(data["public_key"])) != data["node_id"]:
            return jsonify({"error": "node_id does not match public_key"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "invalid public_key"}), 400
    now = int(time.time())
    capacity = max(1, min(int(data.get("capacity", 1)), 1000))
    relay_capable = bool(data.get("relay_capable", True))
    with closing(db()) as connection:
        existing = connection.execute("SELECT mesh_ip FROM nodes WHERE node_id = ?", (data["node_id"],)).fetchone()
        mesh_ip = requested_mesh_ip or (existing["mesh_ip"] if existing else None) or allocate_mesh_ip(connection)
        if mesh_ip:
            owner = connection.execute(
                "SELECT node_id FROM nodes WHERE mesh_ip = ? AND node_id != ?", (mesh_ip, data["node_id"])
            ).fetchone()
            if owner:
                return jsonify({"error": "mesh_ip is already assigned"}), 409
        assigned_role = assign_role(
            connection, data["node_id"], data["role"], data["nat_type"], relay_capable, capacity, now
        )
        connection.execute(
            """INSERT INTO nodes(node_id, public_key, nat_type, role, requested_role, relay_capable, endpoint, mesh_ip, capacity, last_seen, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(node_id) DO UPDATE SET public_key=excluded.public_key,
                  nat_type=excluded.nat_type, role=excluded.role, endpoint=excluded.endpoint,
                  requested_role=excluded.requested_role, relay_capable=excluded.relay_capable,
                  mesh_ip=excluded.mesh_ip, capacity=excluded.capacity, last_seen=excluded.last_seen""",
            (
                data["node_id"], data["public_key"], data["nat_type"], assigned_role, data["role"],
                int(relay_capable), data["endpoint"], mesh_ip, capacity, now, now,
            ),
        )
        connection.commit()
    log(
        f"register node={data['node_id'][:8]} requested={data['role']} assigned={assigned_role} nat={data['nat_type']} "
        f"endpoint={data['endpoint']} mesh_ip={mesh_ip or '-'} capacity={capacity}"
    )
    return jsonify({
        "status": "ok", "mesh_ip": mesh_ip, "mesh_network": str(MESH_IP_NETWORK),
        "assigned_role": assigned_role,
    })


@app.get("/v1/bootstrap/<node_id>")
def bootstrap(node_id):
    if response := require_token():
        return response
    with closing(db()) as connection:
        current = connection.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        if not current:
            log(f"bootstrap unknown node={node_id[:8]}")
            return jsonify({"error": "unknown node"}), 404
        cutoff = int(time.time()) - NODE_TTL_SECONDS
        nodes = connection.execute("SELECT * FROM nodes WHERE last_seen >= ? ORDER BY node_id", (cutoff,)).fetchall()
        superpeers = [row for row in nodes if row["role"] == "superpeer"]
        links = backbone_links(superpeers) + access_links(nodes, superpeers)
        neighbor_ids = {
            link["b"] if link["a"] == node_id else link["a"]
            for link in links if node_id in (link["a"], link["b"])
        }
        peers = [row_to_node(row) for row in nodes if row["node_id"] in neighbor_ids]
        services = [dict(row) for row in connection.execute("SELECT node_id, name FROM services ORDER BY node_id, name")]
    log(
        f"bootstrap node={node_id[:8]} neighbors={len(peers)} superpeers={len(superpeers)} "
        f"services={len(services)}"
    )
    return jsonify({
        "topology_version": topology_version(nodes), "self": row_to_node(current),
        "neighbors": peers, "directory": [row_to_node(row) for row in nodes],
        "backbone_links": links, "services": services,
        "graph_update_mode": "reserved",  # protocol supports a future dynamic optimizer
    })


@app.post("/v1/services")
def publish_service():
    if response := require_token():
        return response
    data = request.get_json(silent=True) or {}
    required = ("node_id", "name", "target_host", "target_port")
    if any(not data.get(field) for field in required):
        return jsonify({"error": "missing required fields"}), 400
    try:
        port = int(data["target_port"])
    except (ValueError, TypeError):
        return jsonify({"error": "invalid target_port"}), 400
    if not 1 <= port <= 65535:
        return jsonify({"error": "invalid target_port"}), 400
    with closing(db()) as connection:
        if not connection.execute("SELECT 1 FROM nodes WHERE node_id = ?", (data["node_id"],)).fetchone():
            log(f"service rejected node={data.get('node_id')} reason=unknown node")
            return jsonify({"error": "unknown node"}), 404
        connection.execute(
            """INSERT INTO services(node_id, name, target_host, target_port, allowed_nodes)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(node_id, name) DO UPDATE SET target_host=excluded.target_host,
                 target_port=excluded.target_port, allowed_nodes=excluded.allowed_nodes""",
            (data["node_id"], data["name"], data["target_host"], port, data.get("allowed_nodes", "*")),
        )
        connection.commit()
    log(
        f"service publish node={data['node_id'][:8]} name={data['name']} "
        f"target={data['target_host']}:{port} allowed={data.get('allowed_nodes', '*')}"
    )
    return jsonify({"status": "ok"})


@app.get("/v1/services/<node_id>/<name>")
def service_details(node_id, name):
    if response := require_token():
        return response
    with closing(db()) as connection:
        service = connection.execute(
            "SELECT * FROM services WHERE node_id = ? AND name = ?", (node_id, name)
        ).fetchone()
    if not service:
        log(f"service lookup miss node={node_id[:8]} name={name}")
        return jsonify({"error": "service not found"}), 404
    log(f"service lookup node={node_id[:8]} name={name}")
    return jsonify(dict(service))


if __name__ == "__main__":
    init_db()
    log(f"starting on 0.0.0.0:{int(os.environ.get('MESH_PORT', '8001'))}")
    app.run(host="0.0.0.0", port=int(os.environ.get("MESH_PORT", "8001")), debug=False)
