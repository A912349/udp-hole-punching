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

## Run the coordinator

```bash
export MESH_NETWORK_TOKEN='a-long-random-secret-of-at-least-24-characters'
./server
```

Useful optional environment variables are `MESH_DATABASE` (default
`mesh.db`), `MESH_PORT` (default `8001`), `MESH_IP_NETWORK` (default
`10.77.0.0/24`), and `MESH_NODE_TTL_SECONDS`.

The coordinator builds a two-tier overlay. Cone NAT relays form the backbone;
ordinary cone clients keep two relay links and symmetric NAT clients keep three
so that a mobile NAT mapping is never the only route. By default, the number
of automatically selected superpeers is `ceil(sqrt(eligible cone relays))`.
Set `MESH_AUTO_SUPERPEERS` to a positive number to pin that count. Advanced
controls are `MESH_BACKBONE_DEGREE` (default `6`), `MESH_CLIENT_LINKS`
(default `2`), and `MESH_SYMMETRIC_LINKS` (default `3`).

## Web administration

Open `http://SERVER_IP:8001/admin`, enter `MESH_NETWORK_TOKEN`, and use the
page to view active nodes and overlay links or change the topology settings.
Changes are stored in `mesh.db`, survive a coordinator restart, immediately
recompute automatic superpeers, and are pushed to connected nodes through the
control WebSocket. The page itself exposes no data until the token is supplied;
serve the coordinator behind HTTPS in production.

## Run a node

```bash
./mesh-node \
  --server http://SERVER_IP:8001 \
  --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-node
```

The node uses STUN to discover its public endpoint and classify the mapping.
For restricted or offline environments, provide both `--nat-type` and
`--public-endpoint HOST:PORT` explicitly. Each node needs its own state
directory because it holds its persistent X25519 identity.

Publish a one-shot TCP service:

```bash
./mesh-node --server http://SERVER_IP:8001 --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-home --service web=127.0.0.1:8080
```

Call it from another node (the destination can be a unique node-ID prefix):

```bash
cat request.bin | ./mesh-node --server http://SERVER_IP:8001 \
  --network-token "$MESH_NETWORK_TOKEN" --state-dir state-client \
  --call NODE_ID:web > response.bin
```

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
