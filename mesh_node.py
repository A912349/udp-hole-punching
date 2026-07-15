"""UDP node for the static two-tier home-service mesh.

This is an overlay router, not a general Internet relay.  A node only forwards
packets when started as a cone superpeer.  The control server distributes the
initial graph; protocol fields and topology versions are intentionally kept so
a later graph optimizer can update it without changing DATA packets.
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import ipaddress
import json
import os
import select
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import requests

from mesh_protocol import (
    Packet,
    ProtocolError,
    b64decode,
    b64encode,
    create_packet,
    decode_packet,
    encode_packet,
    export_private_key,
    export_public_key,
    generate_identity,
    import_private_key,
    node_id,
    open_sealed,
    seal,
)


KEEPALIVE_SECONDS = 10
TOPOLOGY_REFRESH_SECONDS = 5
NODE_HEARTBEAT_SECONDS = 15
LINK_TIMEOUT_SECONDS = 30
LINK_BOOTSTRAP_GRACE_SECONDS = 35
SEEN_PACKET_LIMIT = 10_000
MAX_SERVICE_REQUEST = 32_000
MAX_SERVICE_RESPONSE = 48_000
SERVICE_REQUEST_TIMEOUT = 30
SERVICE_IDLE_TIMEOUT = 2
SYMMETRIC_BURST_SIZE = 500
SYMMETRIC_BURST_TIMEOUT = 45
SYMMETRIC_SCAN_INITIAL_START = -1000
SYMMETRIC_SCAN_INITIAL_END = 2000
SYMMETRIC_SCAN_EXPAND = 2000
SYMMETRIC_SCAN_DELAY = 0.0005
MAX_TUN_PACKET = 1200
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA


def parse_endpoint(value: str) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    port_number = int(port)
    if not host or not 1 <= port_number <= 65535:
        raise ValueError("endpoint must be HOST:PORT")
    return host, port_number


def parse_mesh_ip(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("mesh IP must be an IPv4 address") from error


def load_identity(state_dir: Path):
    state_dir.mkdir(parents=True, exist_ok=True)
    identity_path = state_dir / "identity.json"
    if identity_path.exists():
        data = json.loads(identity_path.read_text(encoding="utf-8"))
        key = import_private_key(data["private_key"])
    else:
        key = generate_identity()
        identity_path.write_text(
            json.dumps({"private_key": export_private_key(key)}, indent=2), encoding="utf-8"
        )
    public_key = export_public_key(key)
    return key, node_id(b64decode(public_key)), public_key


def parse_service(value: str) -> tuple[str, tuple[str, int]]:
    try:
        name, endpoint = value.split("=", 1)
        if not name:
            raise ValueError
        return name, parse_endpoint(endpoint)
    except ValueError as error:
        raise argparse.ArgumentTypeError("service must be NAME=HOST:PORT") from error


class MeshNode:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.private_key, self.node_id, self.public_key = load_identity(Path(args.state_dir))
        self.network_key = hashlib.sha256(args.network_token.encode()).digest()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((args.bind, args.udp_port))
        self.socket.settimeout(1)
        self.stop_event = threading.Event()
        self.started_at = time.monotonic()
        self.neighbors: dict[str, dict[str, Any]] = {}
        self.directory: dict[str, dict[str, Any]] = {}
        self.links: list[dict[str, Any]] = []
        self.topology_version = ""
        self.seen: OrderedDict[str, float] = OrderedDict()
        self.pending: dict[str, tuple[threading.Event, dict[str, Any]]] = {}
        self.pending_lock = threading.Lock()
        self.symmetric_sync_lock = threading.Lock()
        self.symmetric_transport_ready = False
        self.symmetric_scan_lock = threading.Lock()
        self.symmetric_scans: dict[str, threading.Event] = {}
        self.symmetric_connected: set[str] = set()
        self.symmetric_burst_times: dict[str, float] = {}
        self.services = dict(args.service or [])
        self.allowed_nodes = set(args.allow_node or ["*"])
        self.topology_lock = threading.RLock()
        self.tun_fd: int | None = None

    @property
    def headers(self):
        return {"X-Mesh-Token": self.args.network_token}

    def log(self, message: str):
        print(f"[{self.node_id[:8]}] {message}", file=sys.stderr, flush=True)

    def resolve_node_id(self, value: str) -> str:
        """Accept a unique displayed ID prefix while keeping full IDs canonical."""
        with self.topology_lock:
            if value in self.directory:
                return value
            matches = [candidate for candidate in self.directory if candidate.startswith(value)]
        if len(matches) == 1:
            self.log(f"resolved node ID prefix {value} -> {matches[0]}")
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"node ID prefix {value!r} is ambiguous")
        raise ValueError(f"unknown node ID {value!r}; use the full ID shown at startup")

    def detect_endpoint(self):
        """Reuse the STUN classification from the existing UDP transport."""
        if self.args.nat_type != "auto" and self.args.public_endpoint:
            return self.args.public_endpoint, self.args.nat_type
        from client import get_external_and_nat_type

        self.log("detecting external endpoint via STUN")
        (host, port), detected_type = get_external_and_nat_type(self.socket)
        return self.args.public_endpoint or f"{host}:{port}", (
            detected_type if self.args.nat_type == "auto" else self.args.nat_type
        )

    def control_request(self, method: str, path: str, **kwargs):
        response = requests.request(
            method, f"{self.args.server.rstrip('/')}{path}", headers=self.headers, timeout=10, **kwargs
        )
        response.raise_for_status()
        return response.json()

    def registration_payload(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "public_key": self.public_key,
            "nat_type": self.nat_type,
            "role": self.args.role,
            "endpoint": self.endpoint,
            "capacity": self.args.capacity,
            "mesh_ip": self.args.mesh_ip,
        }

    def register_self(self):
        registration = self.control_request("POST", "/v1/register", json=self.registration_payload())
        assigned_ip = registration.get("mesh_ip")
        if not assigned_ip:
            raise RuntimeError("coordinator did not assign mesh_ip")
        if self.args.mesh_ip and self.args.mesh_ip != assigned_ip:
            raise RuntimeError(f"coordinator assigned unexpected mesh IP {assigned_ip}")
        self.args.mesh_ip = assigned_ip

    def register_and_load_topology(self):
        endpoint, nat_type = self.detect_endpoint()
        self.socket.settimeout(1)
        if self.args.role == "superpeer" and nat_type != "cone":
            raise RuntimeError("superpeer requires a cone NAT")
        self.endpoint, self.nat_type = endpoint, nat_type
        self.log(f"registering role={self.args.role} nat_type={nat_type} endpoint={endpoint}")
        self.register_self()
        self.log(f"mesh IP {self.args.mesh_ip}")
        for name, (host, port) in self.services.items():
            self.log(f"publishing service {name} -> {host}:{port}")
            self.control_request(
                "POST", "/v1/services", json={
                    "node_id": self.node_id, "name": name, "target_host": host,
                    "target_port": port, "allowed_nodes": ",".join(sorted(self.allowed_nodes)),
                },
            )
        self.log("requesting topology bootstrap")
        topology = self.control_request("GET", f"/v1/bootstrap/{self.node_id}")
        self.apply_topology(topology)

    def establish_symmetric_transport(self) -> bool:
        """Use the legacy 500-port burst to obtain a usable symmetric-NAT path."""
        if self.nat_type != "symmetric" or self.symmetric_transport_ready:
            return True
        with self.symmetric_sync_lock:
            if self.symmetric_transport_ready:
                return True
            with self.topology_lock:
                peers = [
                    (peer_id, peer["endpoint"])
                    for peer_id, peer in self.neighbors.items()
                    if peer.get("role") == "superpeer"
                ]
            if not peers:
                self.log("symmetric burst deferred: no superpeer in topology")
                return False

            peer_id, endpoint = peers[0]
            peer_address = parse_endpoint(endpoint)
            sockets: list[socket.socket] = []
            selected: socket.socket | None = None
            self.log(f"symmetric NAT: probing {SYMMETRIC_BURST_SIZE} UDP ports via {peer_id[:8]}")
            try:
                for _ in range(SYMMETRIC_BURST_SIZE):
                    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    probe.bind((self.args.bind, 0))
                    probe.setblocking(False)
                    burst = encode_packet(
                        create_packet("SYMMETRIC_BURST", self.node_id, peer_id, {}),
                        self.network_key,
                    )
                    probe.sendto(burst, peer_address)
                    sockets.append(probe)

                deadline = time.monotonic() + SYMMETRIC_BURST_TIMEOUT
                while sockets and time.monotonic() < deadline:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    readable, _, _ = select.select(sockets, [], [], remaining)
                    for probe in readable:
                        try:
                            data, address = probe.recvfrom(65_535)
                            packet = decode_packet(data, self.network_key)
                        except (OSError, ProtocolError):
                            continue
                        if (
                            packet.packet_type == "HELLO"
                            and packet.source == peer_id
                            and packet.destination == self.node_id
                        ):
                            ack = create_packet("HELLO_ACK", self.node_id, peer_id, {})
                            probe.sendto(encode_packet(ack, self.network_key), address)
                            selected = probe
                            break
                    if selected is not None:
                        break

                if selected is None:
                    self.log("symmetric NAT burst timed out without HELLO_ACK")
                    return False

                selected.settimeout(1)
                previous_socket, self.socket = self.socket, selected
                selected = None
                previous_socket.close()
                self.symmetric_transport_ready = True
                self.log(f"symmetric NAT synchronized through {peer_id[:8]} on {self.socket.getsockname()}")
                return True
            finally:
                for probe in sockets:
                    if probe is not selected and probe is not self.socket:
                        probe.close()

    def apply_topology(self, topology: dict[str, Any]) -> bool:
        """Atomic topology replacement; future graph updates call this method."""
        directory = {node["node_id"]: node for node in topology.get("directory", topology["neighbors"])}
        directory[self.node_id] = topology["self"]
        previous_state = self.neighbors
        neighbors = {}
        for node in topology["neighbors"]:
            merged = dict(node)
            for key in ("last_address", "last_rx", "link_up"):
                if key in previous_state.get(node["node_id"], {}):
                    merged[key] = previous_state[node["node_id"]][key]
            neighbors[node["node_id"]] = merged
        with self.topology_lock:
            previous_version = self.topology_version
            previous_neighbors = set(self.neighbors)
            self.directory, self.neighbors = directory, neighbors
            self.links = topology["backbone_links"]
            self.topology_version = topology["topology_version"]
        neighbor_ids = set(neighbors)
        added = sorted(n[:8] for n in (neighbor_ids - previous_neighbors))
        removed = sorted(n[:8] for n in (previous_neighbors - neighbor_ids))
        neighbor_list = ", ".join(sorted(n[:8] for n in neighbors)) or "-"
        if previous_version != self.topology_version or added or removed:
            changes = []
            if added:
                changes.append(f"+{','.join(added)}")
            if removed:
                changes.append(f"-{','.join(removed)}")
            suffix = f" changes={' '.join(changes)}" if changes else ""
            self.log(f"topology={self.topology_version} neighbors={len(neighbors)} [{neighbor_list}]{suffix}")
        if self.args.role == "superpeer":
            # Match the legacy cone-side behaviour: once the coordinator reports
            # a symmetric peer, begin scanning without waiting for its burst to
            # arrive at the cone endpoint.
            for peer_id, peer in neighbors.items():
                if peer.get("nat_type") == "symmetric":
                    self.start_symmetric_scan(peer_id, peer["endpoint"])
        return previous_version != self.topology_version or bool(added or removed)

    def send_to_address(self, packet: Packet, address: tuple[str, int]):
        try:
            self.socket.sendto(encode_packet(packet, self.network_key), address)
        except OSError:
            pass

    def route_next_hop(self, destination: str, log_route: bool = True) -> str | None:
        if destination in self.neighbors:
            if not self.neighbor_usable(destination):
                self.log(f"route neighbor down for {destination[:8]}")
                return None
            if log_route:
                self.log(f"route {destination[:8]} -> direct")
            return destination
        adjacency: dict[str, list[tuple[str, float]]] = {}
        for link in self.links:
            left, right, cost = link["a"], link["b"], float(link.get("cost", 1.0))
            adjacency.setdefault(left, []).append((right, cost))
            adjacency.setdefault(right, []).append((left, cost))
        queue = [(0.0, self.node_id)]
        previous: dict[str, str | None] = {self.node_id: None}
        costs = {self.node_id: 0.0}
        while queue:
            cost, current = heapq.heappop(queue)
            if current == destination:
                break
            if cost != costs.get(current):
                continue
            for candidate, edge_cost in adjacency.get(current, []):
                if current == self.node_id and candidate in self.neighbors and not self.neighbor_usable(candidate):
                    continue
                candidate_cost = cost + edge_cost
                if candidate_cost < costs.get(candidate, float("inf")):
                    costs[candidate] = candidate_cost
                    previous[candidate] = current
                    heapq.heappush(queue, (candidate_cost, candidate))
        if destination not in previous:
            self.log(f"route miss for {destination[:8]}")
            return None
        hop = destination
        while previous[hop] != self.node_id:
            hop = previous[hop]
            if previous[hop] is None:
                self.log(f"route trace broken for {destination[:8]}")
                return None
        if hop != destination and log_route:
            self.log(f"route {destination[:8]} -> next hop {hop[:8]}")
        return hop

    def send_packet(self, packet: Packet):
        is_sync_packet = packet.packet_type in {"HELLO", "HELLO_ACK"}
        with self.topology_lock:
            hop = self.route_next_hop(packet.destination, log_route=not is_sync_packet)
        if not hop:
            self.log(f"no route to {packet.destination[:8]}")
            return False
        with self.topology_lock:
            peer = self.neighbors.get(hop)
        if not peer:
            self.log(f"missing neighbor state for {hop[:8]}")
            return False
        address = peer.get("last_address") or parse_endpoint(peer["endpoint"])
        if not is_sync_packet:
            self.log(
                f"send {packet.packet_type} {packet.source[:8]}->{packet.destination[:8]} via {hop[:8]} "
                f"to {address[0]}:{address[1]}"
            )
        self.send_to_address(packet, address)
        return True

    def send_hello(self, destination: str, packet_type: str = "HELLO"):
        packet = create_packet(packet_type, self.node_id, destination, {"public_key": self.public_key})
        self.send_packet(packet)

    def send_encrypted(
        self, destination: str, message_type: str, body: dict[str, Any], packet_id: str | None = None
    ) -> str | None:
        peer = self.directory.get(destination)
        if not peer:
            self.log(f"unknown destination {destination[:8]}")
            return None
        aad = f"{self.node_id}:{destination}".encode()
        payload = {
            "sealed": seal(
                self.private_key, peer["public_key"],
                json.dumps({"type": message_type, "body": body}, separators=(",", ":")).encode(), aad,
            )
        }
        packet = Packet("DATA", self.node_id, destination, payload, packet_id or secrets.token_hex(12))
        return packet.packet_id if self.send_packet(packet) else None

    def open_tun(self):
        """Create a Linux TUN device; address and routes stay under operator control."""
        if not self.args.tun_name:
            return
        if not self.args.mesh_ip:
            raise RuntimeError("--tun-name requires --mesh-ip")
        if os.name != "posix" or not Path("/dev/net/tun").exists():
            raise RuntimeError("TUN is supported only on Linux with /dev/net/tun available")
        import fcntl
        import struct

        fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            name = self.args.tun_name.encode("ascii")
            if len(name) > 15:
                raise ValueError("TUN interface name must be at most 15 ASCII characters")
            assigned = fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name, IFF_TUN | IFF_NO_PI))
        except Exception:
            os.close(fd)
            raise
        actual_name = assigned[:16].split(b"\0", 1)[0].decode()
        self.tun_fd = fd
        self.log(f"TUN {actual_name} opened for mesh IP {self.args.mesh_ip}; configure it with iproute2")
        if self.args.tun_auto_configure:
            self.configure_tun(actual_name)

    def ip_command(self) -> str:
        """Find iproute2 in Linux or the Termux prefix inherited by root."""
        candidates = [shutil.which("ip"), str(Path(sys.executable).with_name("ip")), "/sbin/ip", "/usr/sbin/ip"]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return candidate
        raise RuntimeError("iproute2 command 'ip' was not found")

    def run_ip(self, ip: str, *arguments: str):
        try:
            subprocess.run([ip, *arguments], check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as error:
            detail = error.stderr.strip() or error.stdout.strip() or str(error)
            raise RuntimeError(f"ip {' '.join(arguments)} failed: {detail}") from error

    def configure_tun(self, name: str):
        """Opt-in host route setup for the mesh subnet, without touching default routes."""
        assert self.args.mesh_ip is not None
        network = ipaddress.IPv4Network(f"{self.args.mesh_ip}/{self.args.mesh_prefix}", strict=False)
        ip = self.ip_command()
        self.run_ip(ip, "link", "set", "dev", name, "mtu", str(MAX_TUN_PACKET), "up")
        self.run_ip(ip, "addr", "replace", f"{self.args.mesh_ip}/{self.args.mesh_prefix}", "dev", name)
        route = ["route", "replace", str(network), "dev", name, "scope", "link", "src", self.args.mesh_ip]
        self.run_ip(ip, *route, "table", "main")

        # Android policy routing often selects an rmnet table before main. Add
        # the same narrow route there; default routes remain untouched.
        result = subprocess.run([ip, "route", "get", "1.1.1.1"], text=True, capture_output=True)
        table_marker = " table "
        if result.returncode == 0 and table_marker in result.stdout:
            table = result.stdout.split(table_marker, 1)[1].split()[0]
            if table not in {"main", "local"}:
                self.run_ip(ip, *route, "table", table)
                self.log(f"TUN route {network} added to main and {table}")
                return
        self.log(f"TUN route {network} added to main")

    def node_for_mesh_ip(self, address: str) -> str | None:
        with self.topology_lock:
            matches = [node_id for node_id, node in self.directory.items() if node.get("mesh_ip") == address]
        return matches[0] if len(matches) == 1 else None

    def handle_tun_packet(self, data: bytes):
        if len(data) < 20 or data[0] >> 4 != 4:
            self.log("drop non-IPv4 packet from TUN")
            return
        if len(data) > MAX_TUN_PACKET:
            self.log(f"drop oversized TUN packet ({len(data)} bytes; MTU is {MAX_TUN_PACKET})")
            return
        source = str(ipaddress.IPv4Address(data[12:16]))
        destination_ip = str(ipaddress.IPv4Address(data[16:20]))
        if source != self.args.mesh_ip:
            self.log(f"drop TUN packet with non-mesh source {source}")
            return
        destination = self.node_for_mesh_ip(destination_ip)
        if not destination:
            self.log(f"no mesh node owns TUN destination {destination_ip}")
            return
        self.log(f"TUN IPv4 {source}->{destination_ip} via {destination[:8]} bytes={len(data)}")
        self.send_encrypted(destination, "IP_PACKET", {"data": b64encode(data)})

    def tun_loop(self):
        assert self.tun_fd is not None
        while not self.stop_event.is_set():
            try:
                readable, _, _ = select.select([self.tun_fd], [], [], 1)
                if readable:
                    self.handle_tun_packet(os.read(self.tun_fd, MAX_TUN_PACKET + 1))
            except OSError:
                if not self.stop_event.is_set():
                    self.log("TUN read failed")
                return

    def handle_ip_packet(self, source: str, body: dict[str, Any]):
        if self.tun_fd is None:
            self.log(f"drop IP packet from {source[:8]}: TUN is disabled")
            return
        try:
            data = b64decode(body["data"])
            if len(data) < 20 or len(data) > MAX_TUN_PACKET or data[0] >> 4 != 4:
                raise ValueError("invalid IPv4 packet")
            source_ip = str(ipaddress.IPv4Address(data[12:16]))
            destination_ip = str(ipaddress.IPv4Address(data[16:20]))
            with self.topology_lock:
                expected_source_ip = self.directory.get(source, {}).get("mesh_ip")
            if source_ip != expected_source_ip:
                raise ValueError(f"packet source {source_ip} does not belong to sender")
            if destination_ip != self.args.mesh_ip:
                raise ValueError(f"packet destination {destination_ip} is not local mesh IP")
            os.write(self.tun_fd, data)
            self.log(f"TUN IPv4 delivered from {source[:8]} bytes={len(data)}")
        except (KeyError, ValueError, OSError) as error:
            self.log(f"drop IP packet from {source[:8]}: {error}")

    def remember(self, packet_id: str) -> bool:
        if packet_id in self.seen:
            return False
        self.seen[packet_id] = time.monotonic()
        while len(self.seen) > SEEN_PACKET_LIMIT:
            self.seen.popitem(last=False)
        return True

    def handle_data(self, packet: Packet):
        peer = self.directory.get(packet.source)
        if not peer:
            # A client may be registered between two regular topology polls.
            # Refresh once before discarding a DATA packet that could be valid.
            self.log(f"DATA from new source {packet.source[:8]}; refreshing topology")
            try:
                self.refresh_topology()
            except requests.RequestException as error:
                self.log(f"topology refresh for DATA failed: {error}")
                return
            peer = self.directory.get(packet.source)
            if not peer:
                self.log(f"drop DATA from unknown source {packet.source[:8]}")
                return
        try:
            raw = open_sealed(
                self.private_key, peer["public_key"], packet.payload["sealed"],
                f"{packet.source}:{self.node_id}".encode(),
            )
            message = json.loads(raw)
        except (KeyError, ValueError, ProtocolError):
            return
        message_type, body = message.get("type"), message.get("body", {})
        if message_type == "SERVICE_REQUEST":
            self.log(f"service request {body.get('service')} from {packet.source[:8]} id={packet.packet_id[:8]}")
            self.handle_service_request(packet.source, packet.packet_id, body)
        elif message_type == "SERVICE_RESPONSE":
            request_id = body.get("request_id")
            with self.pending_lock:
                pending = self.pending.get(request_id)
            if pending:
                event, result = pending
                result.update(body)
                detail = f"error={body['error']}" if "error" in body else f"bytes={len(b64decode(body['data']))}"
                self.log(
                    f"service response for request={request_id[:8]} {detail}"
                )
                event.set()
        elif message_type == "IP_PACKET":
            self.handle_ip_packet(packet.source, body)

    def handle_service_request(self, source: str, request_id: str, body: dict[str, Any]):
        name = body.get("service")
        if name not in self.services or ("*" not in self.allowed_nodes and source not in self.allowed_nodes):
            self.log(f"service denied name={name} from {source[:8]}")
            self.send_encrypted(source, "SERVICE_RESPONSE", {"request_id": request_id, "error": "service unavailable"})
            return
        try:
            request_data = b64decode(body["data"])
            if len(request_data) > MAX_SERVICE_REQUEST:
                raise ValueError("request too large")
            host, port = self.services[name]
            self.log(f"service call name={name} target={host}:{port} request_bytes={len(request_data)}")
            with socket.create_connection((host, port), timeout=5) as service_socket:
                service_socket.settimeout(SERVICE_IDLE_TIMEOUT)
                service_socket.sendall(request_data)
                chunks: list[bytes] = []
                total = 0
                while True:
                    try:
                        chunk = service_socket.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_SERVICE_RESPONSE:
                        raise ValueError("response too large")
                response = b"".join(chunks)
            self.log(f"service reply name={name} response_bytes={len(response)}")
            response_body = {"request_id": request_id, "data": b64encode(response)}
        except (OSError, KeyError, ValueError) as error:
            self.log(f"service error name={name}: {error}")
            response_body = {"request_id": request_id, "error": str(error)}
        self.send_encrypted(source, "SERVICE_RESPONSE", response_body)

    def handle_hello(self, packet: Packet, address: tuple[str, int]):
        with self.topology_lock:
            known_neighbor = packet.source in self.neighbors
        if not known_neighbor:
            # A later-starting client sends HELLO before its first DATA packet.
            # Refresh now so DATA is not dropped during the normal poll interval.
            self.log(f"rx HELLO from new node {packet.source[:8]}; refreshing topology")
            try:
                self.refresh_topology()
            except requests.RequestException as error:
                self.log(f"topology refresh after HELLO failed: {error}")
        with self.topology_lock:
            neighbor = self.neighbors.get(packet.source)
            if neighbor is not None:
                neighbor["last_address"] = address
        if neighbor is not None:
            self.send_hello(packet.source, "HELLO_ACK")

    def handle_symmetric_burst(self, packet: Packet):
        """Start the cone-side port sweep used by the legacy symmetric client."""
        if self.args.role != "superpeer":
            return
        with self.topology_lock:
            neighbor = self.neighbors.get(packet.source)
        if neighbor is None:
            self.log(f"rx symmetric burst from new node {packet.source[:8]}; refreshing topology")
            try:
                self.refresh_topology()
            except requests.RequestException as error:
                self.log(f"topology refresh after symmetric burst failed: {error}")
                return
            with self.topology_lock:
                neighbor = self.neighbors.get(packet.source)
        if neighbor is None or neighbor.get("nat_type") != "symmetric":
            return

        now = time.monotonic()
        with self.symmetric_scan_lock:
            previous_burst = self.symmetric_burst_times.get(packet.source, 0)
            self.symmetric_burst_times[packet.source] = now
        # One burst contains 500 packets.  A short cooldown keeps that one
        # handshake from restarting the scan after it has already connected.
        if now - previous_burst < 5:
            return
        self.start_symmetric_scan(packet.source, neighbor["endpoint"], force=True)

    def start_symmetric_scan(self, peer_id: str, endpoint: str, force: bool = False):
        """Start at most one legacy port scan for a symmetric direct neighbor."""
        with self.symmetric_scan_lock:
            if peer_id in self.symmetric_scans:
                return
            if peer_id in self.symmetric_connected and not force:
                return
            if force:
                self.symmetric_connected.discard(peer_id)
            completed = threading.Event()
            self.symmetric_scans[peer_id] = completed
        threading.Thread(
            target=self.scan_symmetric_neighbor,
            args=(peer_id, endpoint, completed),
            daemon=True,
        ).start()

    def scan_symmetric_neighbor(self, peer_id: str, endpoint: str, completed: threading.Event):
        """Probe the peer's STUN port range until its burst socket replies."""
        try:
            host, base_port = parse_endpoint(endpoint)
            scanned_ports: set[int] = set()
            start_offset, end_offset = SYMMETRIC_SCAN_INITIAL_START, SYMMETRIC_SCAN_INITIAL_END
            self.log(f"symmetric scan for {peer_id[:8]} around {host}:{base_port}")
            while not completed.is_set():
                start = max(1, base_port + start_offset)
                end = min(65535, base_port + end_offset)
                for port in range(start, end + 1):
                    if completed.is_set():
                        break
                    if port in scanned_ports:
                        continue
                    scanned_ports.add(port)
                    self.send_to_address(
                        create_packet("HELLO", self.node_id, peer_id, {"public_key": self.public_key}),
                        (host, port),
                    )
                    time.sleep(SYMMETRIC_SCAN_DELAY)
                if completed.is_set() or (start == 1 and end == 65535):
                    break
                start_offset -= SYMMETRIC_SCAN_EXPAND
                end_offset += SYMMETRIC_SCAN_EXPAND
            if completed.is_set():
                with self.symmetric_scan_lock:
                    self.symmetric_connected.add(peer_id)
                self.log(f"symmetric scan connected to {peer_id[:8]}")
            else:
                self.log(f"symmetric scan exhausted UDP ports for {peer_id[:8]}")
        finally:
            with self.symmetric_scan_lock:
                if self.symmetric_scans.get(peer_id) is completed:
                    self.symmetric_scans.pop(peer_id, None)

    def complete_symmetric_scan(self, peer_id: str):
        with self.symmetric_scan_lock:
            completed = self.symmetric_scans.get(peer_id)
        if completed is not None:
            completed.set()

    def remember_neighbor_address(self, source: str, address: tuple[str, int]):
        """Use the NAT mapping observed on authenticated traffic for replies."""
        with self.topology_lock:
            neighbor = self.neighbors.get(source)
            if neighbor is not None:
                neighbor["last_address"] = address
                neighbor["last_rx"] = time.monotonic()

    def neighbor_usable(self, peer_id: str) -> bool:
        peer = self.neighbors.get(peer_id)
        if peer is None:
            return False
        last_rx = peer.get("last_rx")
        if last_rx is None:
            return time.monotonic() - self.started_at < LINK_BOOTSTRAP_GRACE_SECONDS
        return time.monotonic() - last_rx <= LINK_TIMEOUT_SECONDS

    def receive_loop(self):
        while not self.stop_event.is_set():
            try:
                data, address = self.socket.recvfrom(65_535)
                packet = decode_packet(data, self.network_key)
            except socket.timeout:
                continue
            except (OSError, ProtocolError):
                continue
            if not self.remember(packet.packet_id):
                continue
            self.remember_neighbor_address(packet.source, address)
            if packet.destination != self.node_id:
                if self.args.role == "superpeer":
                    try:
                        self.log(
                            f"forward {packet.packet_type} {packet.source[:8]}->{packet.destination[:8]} "
                            f"ttl={packet.ttl}"
                        )
                        self.send_packet(packet.decrement_ttl())
                    except ProtocolError:
                        pass
                continue
            if packet.packet_type == "HELLO":
                self.handle_hello(packet, address)
            elif packet.packet_type == "HELLO_ACK" and packet.source in self.neighbors:
                self.neighbors[packet.source]["last_address"] = address
                self.complete_symmetric_scan(packet.source)
            elif packet.packet_type == "SYMMETRIC_BURST":
                self.handle_symmetric_burst(packet)
            elif packet.packet_type == "DATA":
                self.handle_data(packet)

    def keepalive_loop(self):
        while not self.stop_event.wait(KEEPALIVE_SECONDS):
            with self.topology_lock:
                peers = tuple(self.neighbors)
            for peer_id in peers:
                self.send_hello(peer_id)

    def heartbeat_loop(self):
        while not self.stop_event.wait(NODE_HEARTBEAT_SECONDS):
            try:
                self.register_self()
            except requests.RequestException as error:
                self.log(f"coordinator heartbeat failed: {error}")

    def link_health_loop(self):
        while not self.stop_event.wait(KEEPALIVE_SECONDS):
            with self.topology_lock:
                peers = tuple(self.neighbors.items())
            for peer_id, peer in peers:
                usable = self.neighbor_usable(peer_id)
                if peer.get("link_up") != usable:
                    peer["link_up"] = usable
                    state = "up" if usable else "down"
                    self.log(f"link {peer_id[:8]} {state}")

    def refresh_topology(self) -> bool:
        """Fetch the current graph before routing traffic from a new neighbor."""
        topology = self.control_request("GET", f"/v1/bootstrap/{self.node_id}")
        return self.apply_topology(topology)

    def refresh_topology_loop(self):
        # Re-bootstrap periodically so a restarted peer or changed endpoint is
        # picked up without manual restarts.
        while not self.stop_event.wait(TOPOLOGY_REFRESH_SECONDS):
            try:
                changed = self.refresh_topology()
                if changed:
                    for peer_id in tuple(self.neighbors):
                        self.send_hello(peer_id)
            except requests.RequestException as error:
                self.log(f"topology refresh failed: {error}")

    def start(self):
        self.register_and_load_topology()
        self.establish_symmetric_transport()
        self.open_tun()
        threading.Thread(target=self.receive_loop, daemon=True).start()
        if self.tun_fd is not None:
            threading.Thread(target=self.tun_loop, daemon=True).start()
        threading.Thread(target=self.keepalive_loop, daemon=True).start()
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.link_health_loop, daemon=True).start()
        threading.Thread(target=self.refresh_topology_loop, daemon=True).start()
        for peer_id in self.neighbors:
            self.send_hello(peer_id)
        self.log(f"listening on {self.socket.getsockname()}")

    def request_service(self, destination: str, name: str, request_data: bytes, timeout: float = SERVICE_REQUEST_TIMEOUT):
        if self.nat_type == "symmetric" and not self.symmetric_transport_ready:
            self.refresh_topology()
            if not self.establish_symmetric_transport():
                raise RuntimeError("symmetric NAT synchronization with a superpeer failed")
        destination = self.resolve_node_id(destination)
        event, result = threading.Event(), {}
        request_id = secrets.token_hex(12)
        with self.pending_lock:
            self.pending[request_id] = (event, result)
        try:
            self.log(f"request service {name} -> {destination[:8]} bytes={len(request_data)}")
            if not self.send_encrypted(
                destination, "SERVICE_REQUEST", {"service": name, "data": b64encode(request_data)}, request_id
            ):
                raise RuntimeError("could not send service request")
            if not event.wait(timeout):
                raise TimeoutError("service response timed out")
            if "error" in result:
                raise RuntimeError(result["error"])
            self.log(f"service completed request={request_id[:8]}")
            return b64decode(result["data"])
        finally:
            with self.pending_lock:
                self.pending.pop(request_id, None)

    def close(self):
        self.stop_event.set()
        self.socket.close()
        if self.tun_fd is not None:
            os.close(self.tun_fd)
            self.tun_fd = None


def parse_args():
    parser = argparse.ArgumentParser(description="Two-tier UDP home-service mesh node")
    parser.add_argument("--server", required=True, help="Control-plane base URL")
    parser.add_argument("--network-token", required=True, help="Shared control/overlay network token")
    parser.add_argument("--role", choices=("superpeer", "client"), default="client")
    parser.add_argument("--nat-type", choices=("auto", "cone", "symmetric"), default="auto")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--udp-port", type=int, default=0)
    parser.add_argument("--public-endpoint", help="Known public UDP endpoint HOST:PORT")
    parser.add_argument("--mesh-ip", type=parse_mesh_ip, help="Optional static mesh IPv4 address; omitted uses coordinator lease")
    parser.add_argument("--tun-name", help="Create a Linux TUN interface for --mesh-ip")
    parser.add_argument("--mesh-prefix", type=int, default=24, choices=range(1, 31), help="CIDR prefix for --mesh-ip")
    parser.add_argument("--tun-auto-configure", action="store_true", help="Configure TUN address and mesh-only routes")
    parser.add_argument("--capacity", type=int, default=1)
    parser.add_argument("--state-dir", default="mesh-state")
    parser.add_argument("--service", action="append", type=parse_service, help="Publish NAME=HOST:PORT")
    parser.add_argument("--allow-node", action="append", help="Node ID permitted to use local services")
    parser.add_argument("--call", metavar="NODE_ID:SERVICE", help="Send one request to a remote local service")
    parser.add_argument("--request-file", help="Bytes sent with --call; stdin is used when omitted")
    return parser.parse_args()


def main():
    args = parse_args()
    if len(args.network_token) < 24:
        raise SystemExit("--network-token must be at least 24 characters")
    node = MeshNode(args)
    try:
        node.log(f"Mesh node {node.node_id}")
        node.start()
        if args.call:
            destination, service = args.call.split(":", 1)
            request_data = Path(args.request_file).read_bytes() if args.request_file else sys.stdin.buffer.read()
            sys.stdout.buffer.write(node.request_service(destination, service, request_data))
            return
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        node.close()


if __name__ == "__main__":
    main()
