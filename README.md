# Home UDP Mesh (Go)

This is the Go implementation of the home UDP mesh. It contains a WebSocket
control plane (legacy HTTP endpoints remain for compatibility), an encrypted
UDP overlay node with Linux TUN support, and the stand-alone UDP
hole-punching experiment. Mesh nodes keep one connection open at `/v1/ws`;
the coordinator pushes topology snapshots immediately after a node changes,
without 5-second HTTP polling. The control plane never relays user packets.

## Build

Install Go 1.22 or newer, then run:

```bash
go mod tidy
go build ./...
```

The commands are built as `server`, `mesh-node`, and `punch-client` (their
source is under `cmd/`). `modernc.org/sqlite` is a pure-Go SQLite driver, so a
C compiler is not required.

### OpenWrt routers (MIPS)

CI (`.github/workflows/go.yml`) publishes a ready `mesh-node-linux-mipsle`
artifact on every push to `main`. It targets `mipsel_24kc` devices such as
MediaTek MT7621 routers (Xiaomi CR6606/CR6608, and similar): MIPS32r2,
little-endian, no FPU, so the build is `mipsle` with `GOMIPS=softfloat`.

To cross-compile by hand:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
  go build -trimpath -ldflags="-s -w" -o mesh-node-linux-mipsle ./cmd/mesh-node
```

Notes for routers:

- The binary is fully static, so it runs on any OpenWrt userland. Install the
  TUN kernel module first: `opkg install kmod-tun` (the node creates
  `/dev/net/tun` itself).
- The coordinator (`server`) is not available for `mipsle` because
  `modernc.org/sqlite` does not support that platform; run the coordinator on
  a regular host and point the router node at it.
- On devices with 128–256 MB of RAM, cap the Go heap, e.g. add
  `GOGC=40 GOMEMLIMIT=48MiB` to the service environment.

#### Remote peers and the OpenWrt firewall

Remote (non-LAN) peers reach a relay/superpeer node by sending UDP to its
public endpoint. OpenWrt's default `wan` input policy is `REJECT`, which
silently kills hole punching, while LAN peers keep working through broadcast
discovery — a symptom that "everything works except remote nodes". Two steps
fix it:

1. Pin the node's UDP port (without the flag it is ephemeral and changes on
   every restart):

   ```sh
   mesh-node -udp-port 41820
   ```

2. Allow that port on the WAN:

   ```sh
   uci -q delete firewall.mesh_udp
   uci set firewall.mesh_udp=rule
   uci set firewall.mesh_udp.name='mesh-node-udp'
   uci set firewall.mesh_udp.src='wan'
   uci set firewall.mesh_udp.proto='udp'
   uci set firewall.mesh_udp.dest_port='41820'
   uci set firewall.mesh_udp.target='ACCEPT'
   uci commit firewall
   /etc/init.d/firewall restart
   ```

`openwrt/mesh-node.init` is a ready procd init script that pins the port,
remembers the state file across restarts and starts the node at boot.

## Run the coordinator

```bash
# Optional: if omitted, a token is generated and printed on first startup.
# $env:MESH_ACCOUNT_BOOTSTRAP_TOKEN='a-long-random-bootstrap-secret'
./server
```

Useful optional environment variables are `MESH_DATABASE` (default
`mesh.db`), `MESH_PORT` (default `8001`), `MESH_IP_NETWORK` (default
`10.77.0.0/24`), `MESH_NODE_TTL_SECONDS`, and `MESH_NETWORK_TOKEN` for
legacy single-network compatibility.

The coordinator builds a two-tier overlay. Cone NAT relays form the backbone;
ordinary cone clients keep two relay links and symmetric NAT clients keep three
so that a mobile NAT mapping is never the only route. By default, the number
of automatically selected superpeers is `ceil(sqrt(eligible cone relays))`.
Set `MESH_AUTO_SUPERPEERS` to a positive number to pin that count. Advanced
controls are `MESH_BACKBONE_DEGREE` (default `6`), `MESH_CLIENT_LINKS`
(default `2`), and `MESH_SYMMETRIC_LINKS` (default `3`).

## Web administration

Open `https://SERVER_IP:8001/admin` and create the first account using the
bootstrap secret printed by the server as the registration invite. Registration returns that
account's own network token. Passwords are stored as bcrypt hashes, and
subsequent accounts can only be registered with a one-use account invitation.
Sessions use an HttpOnly cookie plus a CSRF token; the raw session token is
never stored in SQLite.

Each account has an independent network token. Only devices registered with
that token appear in the account's topology and can be administered by it.
The legacy `MESH_NETWORK_TOKEN` is optional and remains available for old
single-network deployments. Account login is for the web administration plane
and does not require changing the node client or WebSocket protocol. For native HTTPS, set
both `MESH_TLS_CERT` and `MESH_TLS_KEY`; otherwise put the coordinator behind
an HTTPS reverse proxy. Do not expose the login endpoints over plain HTTP.
`MESH_COOKIE_SECURE=true` can be set when TLS is terminated by a proxy.

Changes are stored in `mesh.db`, survive a coordinator restart, immediately
recompute automatic superpeers, and are pushed to connected nodes through the
control WebSocket. The page exposes no network data until an account or the
legacy network token is authenticated.

## Run a node

```bash
./mesh-node \
  --server https://SERVER_IP:8001 \
  --network-token "$ACCOUNT_NETWORK_TOKEN" \
  --state-dir mesh-node.json
```

The node uses STUN to discover its public endpoint and classify the mapping.
For restricted or offline environments, provide both `--nat-type` and
`--public-endpoint HOST:PORT` explicitly. Each node needs its own state JSON
file because it holds its persistent X25519 identity and configuration.

For symmetric NAT traversal, `--symmetric-scan-step` controls the interval
between ports in each scan pass (default: `200`). For example, a target port
of `54532` is probed as `54332`, `54732`, and so on through the port range;
the following pass is centered on `54531`.

Publish a one-shot TCP service:

```bash
./mesh-node --server https://SERVER_IP:8001 --network-token "$ACCOUNT_NETWORK_TOKEN" \
  --state-dir mesh-node.json --service web=127.0.0.1:8080
```

Call it from another node (the destination can be a unique node-ID prefix):

```bash
cat request.bin | ./mesh-node --server https://SERVER_IP:8001 \
  --network-token "$ACCOUNT_NETWORK_TOKEN" --state-dir mesh-node.json \
  --call NODE_ID:web > response.bin
```

## Client self-update

The admin panel (Settings → "Client updates") can distribute new `mesh-node`
builds to the running fleet. Two sources per architecture are supported —
`linux/amd64`, `linux/arm64`, `linux/mipsle` and `windows/amd64`:

- **Stored binary** — upload the file in the admin panel; it is kept in the
  coordinator's SQLite database and served to nodes at
  `/v1/update/binaries/{arch}` (authenticated with the node's network token).
- **Download link** — any HTTPS URL, for example a GitHub release artifact.

"Send update" (for one selected node or all connected nodes) pushes an
`update` event over the control WebSocket. The node downloads the binary for
its `runtime.GOOS/GOARCH` in the background (stored binaries win over
links), verifies the announced size and SHA-256, and replaces its own
executable. The installed path never changes, so systemd units, OpenWrt
init scripts and Windows `HKCU\...\Run` autostart entries keep working
without re-registration:

- On Linux/macOS/BSD the new file is renamed over the running executable
  (atomic) and the process re-executes itself in place (`syscall.Exec`).
- On Windows the running `.exe` is renamed to `mesh-node.exe.old`, the new
  file takes the original name, and a new process starts; the leftover
  `.old` file is removed on the next start.

Per-node progress (`restarting` / `failed` with the reason) is reported back
and shown in the admin panel; update actions are recorded in the audit log.
Nodes report their architecture (`goarch`) during registration, so the panel
knows which build each device would receive.

## Security and compatibility

The data plane authenticates UDP envelopes with HMAC-SHA-256, uses X25519 key
agreement, and encrypts end-to-end data with ChaCha20-Poly1305. The identity
file format and JSON packet format intentionally remain compatible with the
previous implementation, so a node can reuse an existing `identity.json`.

The service transport remains request/response rather than a reliable TCP
tunnel: it is appropriate for small requests and short HTTP responses, not
for SSH, RDP, or long streams.

## Windows client

The coordinator remains a Linux service, while `mesh-node.exe` can run on
Windows using the official Wintun adapter. See [WINDOWS_CLIENT.md](WINDOWS_CLIENT.md)
for installation, elevation and firewall requirements. Windows uses the same
encrypted UDP/WebSocket protocol and topology as Linux; only the virtual
adapter, route and DNS integration are platform-specific.
## Site-to-site routes and mesh DNS

Open a peer in **Admin → Topology** to assign a DNS name, one or more LAN CIDRs
(for example `192.168.1.0/24`) and LAN object names. The coordinator assigns
every LAN a stable, unique prefix from `10.77.0.0/16`. Thus two sites may both
use `192.168.1.0/24`: they appear in the mesh as, for example,
`10.77.1.0/24` and `10.77.2.0/24`. Gateway nodes perform stateless 1:1 prefix
translation. Linux nodes install the virtual routes and remove stale routes.

The gateway host must have IPv4 forwarding enabled, and its physical LAN must
have a return route to the remote virtual networks. On Linux, when `iptables`
is available, the node automatically installs narrowly scoped MASQUERADE rules
for these site-to-site flows and enables IPv4 forwarding; otherwise configure
equivalent forwarding/NAT policy manually.

Each node starts a small UDP DNS proxy on its unique mesh address at port 53.
It does not claim `127.0.0.1:53`, because that address is commonly owned by a
system resolver and is shared by all mesh-node processes on a host. If the mesh
address is not available yet (for example, when TUN is disabled), the proxy
falls back to `127.0.0.1:5353`, or an automatically selected local port if that
port is already occupied. Queries such as `office.mesh`, `printer.mesh`, and
`<node-id-prefix>.mesh` resolve from the mesh directory; other queries are
forwarded to the resolver from `/etc/resolv.conf`, while addresses in the
`10.77.0.0/16` mesh pool are ignored as upstreams to avoid resolver loops.
`1.1.1.1:53` is used only when no usable upstream is found.

On Linux with `systemd-resolved`, the mesh address is installed as the DNS
server for the TUN interface and `~mesh` plus `mesh` search routing is enabled.
Without it, a real `/etc/resolv.conf` is updated with the mesh address and
`search mesh`; symlink-managed resolver files are not modified. A loopback
fallback can be integrated automatically through dnsmasq using a
`127.0.0.1#port` forwarding rule. LAN objects are entered as `name=physical-ip`;
DNS returns their automatically mapped `10.77.x.x` address.
