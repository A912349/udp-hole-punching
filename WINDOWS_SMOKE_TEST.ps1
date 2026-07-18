param(
    [string]$AdapterName = 'mesh0',
    [string[]]$Peer = @()
)

$ErrorActionPreference = 'Stop'

Write-Host "[1/4] Checking adapter '$AdapterName'..."
$adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
if ($adapter.Status -eq 'Disabled') {
    throw "Adapter '$AdapterName' is disabled"
}
Write-Host "      Status: $($adapter.Status), ifIndex: $($adapter.ifIndex)"

Write-Host '[2/4] Checking IPv4 address...'
$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if ($addresses.Count -eq 0) {
    throw "No IPv4 address is assigned to '$AdapterName'"
}
$addresses | ForEach-Object { Write-Host "      $($_.IPAddress)/$($_.PrefixLength)" }

Write-Host '[3/4] Checking mesh route...'
$routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if ($routes.Count -eq 0) {
    throw "No IPv4 route is attached to '$AdapterName'"
}
$routes | Sort-Object DestinationPrefix | ForEach-Object {
    Write-Host "      $($_.DestinationPrefix) -> $($_.NextHop), metric $($_.RouteMetric)"
}

Write-Host '[4/4] Checking firewall rule...'
$rules = @(Get-NetFirewallRule -DisplayName 'Home UDP Mesh inbound *' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True')
if ($rules.Count -eq 0) {
    Write-Warning 'The mesh inbound firewall rule is absent; UDP replies may be blocked.'
} else {
    $rules | ForEach-Object { Write-Host "      $($_.DisplayName)" }
}

if ($Peer.Count -gt 0) {
    Write-Host "Testing mesh peers: $($Peer -join ', ')"
    foreach ($address in $Peer) {
        if (Test-Connection -TargetName $address -Count 3 -Quiet) {
            Write-Host "      PASS $address" -ForegroundColor Green
        } else {
            Write-Host "      FAIL $address" -ForegroundColor Red
        }
    }
}

Write-Host 'Windows mesh smoke test completed.' -ForegroundColor Green
