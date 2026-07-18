# Windows client

`mesh-node.exe` is a Windows-only client for the Linux coordinator. The UDP
overlay, WebSocket control plane, encryption and topology format are the same
as on Linux; the Windows data-plane adapter is provided by the official
[Wintun](https://www.wintun.net/) runtime.

## Installation

1. Put `mesh-node.exe` and the matching `wintun.dll` in the same directory.
   The Windows CI artifact already contains both files.
2. Open **PowerShell as Administrator**. Creating/configuring a virtual
   adapter and changing its routes/DNS requires elevation.
3. Allow the selected UDP port through Windows Firewall if the machine is
   behind a restrictive local firewall. The client now attempts to create a
   program-scoped inbound UDP rule automatically; if it cannot, the log prints
   the exact port to allow manually.

The first start creates a persistent adapter named `mesh0` and installs the
signed Wintun driver. It does not install or require WireGuard itself.

## Start

```powershell
.\mesh-node.exe `
  --server http://LINUX_SERVER:8001 `
  --network-token "a-long-random-secret-of-at-least-24-characters" `
  --state-dir "$env:ProgramData\HomeUdpMesh\state" `
  --tun-name mesh0 `
  --tun-auto-configure
```

The client assigns the coordinator-provided mesh address to Wintun, adds only
the mesh and advertised site routes, and configures the mesh DNS listener on
the adapter. The normal Windows default route is not replaced. `Ctrl+C`
closes the UDP/WebSocket session, removes routes owned by the process and
restores adapter DNS to DHCP.

If the adapter name is already used by another Wintun instance, choose another
name with `--tun-name`. Each client must use its own `--state-dir` and identity.

## Troubleshooting

- `load wintun.dll`: copy the architecture-matching Wintun DLL beside the
  executable; do not use an x86 DLL with an amd64 executable.
- `open or create Wintun adapter`: run the terminal elevated and remove a
  broken stale adapter from **Network Connections**, then retry.
- `route.exe` or `netsh` errors: check that the terminal is elevated and that
  the adapter name is not longer than Windows allows.

The current client is intentionally console-first so it can run unattended as
a scheduled task or service. Its saved configuration and all operational
flags are identical to the Linux client; a GUI can be layered on top without
changing the protocol.
