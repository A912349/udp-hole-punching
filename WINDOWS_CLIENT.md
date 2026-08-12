# Windows client

`mesh-node.exe` is a Windows-only client for the Linux coordinator. The UDP
overlay, WebSocket control plane, encryption and topology format are the same
as on Linux; the Windows data-plane adapter is provided by the official
[Wintun](https://www.wintun.net/) runtime.

## Installation

1. Put `mesh-node.exe` in a directory of your choice. The Windows build embeds
   the matching `wintun.dll` and extracts it to `%TEMP%` automatically.
2. Open **PowerShell as Administrator**. Creating/configuring a virtual
adapter and changing its routes/DNS requires elevation.
3. Allow the selected UDP port through Windows Firewall if the machine is
   behind a restrictive local firewall. The client now attempts to create a
   program-scoped inbound UDP rule automatically; if it cannot, the log prints
   the exact port to allow manually. A second rule is created for the local
   LAN discovery port (`37777/udp`).

The first start creates a persistent adapter named `mesh0` and installs the
signed Wintun driver. It does not install or require WireGuard itself.

## Start

```powershell
.\mesh-node.exe `
  --server http://LINUX_SERVER:8001 `
  --network-token "ACCOUNT_NETWORK_TOKEN" `
  --state-dir "$env:ProgramData\HomeUdpMesh\mesh-node.json" `
  --tun-name mesh0 `
  --tun-auto-configure
```

The client assigns the coordinator-provided mesh address to Wintun, adds only
the mesh and advertised site routes, and configures the mesh DNS listener on
the adapter. The normal Windows default route is not replaced. `Ctrl+C`
closes the UDP/WebSocket session, removes routes owned by the process and
restores adapter DNS to DHCP.

If the adapter name is already used by another Wintun instance, choose another
name with `--tun-name`. Each client must use its own state JSON file and identity.

The current format stores configuration and the persistent X25519 private key in
one `mesh-node.json` file. Older installations using `mesh-node-config.json`
and `<state-dir>\identity.json` are migrated automatically on first start.

Run the local smoke test from the repository after starting the client:

```powershell
.\WINDOWS_SMOKE_TEST.ps1 -Peer 10.77.0.1,10.77.0.2
```

It verifies the adapter state, assigned IPv4 address, routes and the inbound
firewall rule before testing the selected mesh peers.

Nodes periodically broadcast an authenticated LAN discovery packet on UDP
port `37777`. When a peer is on the same LAN, its private UDP endpoint is used
instead of relying on NAT hairpinning through the public STUN endpoint. If a
link becomes stale, the node re-runs STUN, re-registers its endpoint, refreshes
topology and retries the handshake.

## Troubleshooting

- `load embedded wintun.dll`: the executable contains the amd64 Wintun DLL and
  extracts it to `%TEMP%` automatically.
- `open or create Wintun adapter`: run the terminal elevated and remove a
  broken stale adapter from **Network Connections**, then retry.
- `route.exe` or `netsh` errors: check that the terminal is elevated and that
  the adapter name is not longer than Windows allows.

The current client is intentionally console-first so it can run unattended as
a scheduled task or service. Its saved configuration and all operational
flags are identical to the Linux client; a GUI can be layered on top without
changing the protocol.
