# Collector-Min.ps1 — Minimal, remediation-free environment snapshot (Windows)
# Output: JSON to .\out\system_snapshot_windows.json

Param()
$ErrorActionPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path ".\out" | Out-Null
$out = ".\out\system_snapshot_windows.json"
$ts = (Get-Date).ToString("o")

function Sanitize([string]$s) {
  if (-not $s) { return "" }
  return ($s -replace '[\x00-\x1F]', '' ) -replace '\\', '\\\\' -replace '"','\"'
}

function TryCmd([scriptblock]$block) {
  try { & $block | Out-String } catch { "" }
}

$os = (Get-CimInstance Win32_OperatingSystem)
$cs = (Get-CimInstance Win32_ComputerSystem)
$bios = (Get-CimInstance Win32_BIOS)

$services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 200 | Format-Table -AutoSize | Out-String
$processes = Get-Process | Sort-Object -Property PM -Descending | Select-Object -First 200 | Format-Table -AutoSize | Out-String
$ports = TryCmd { netstat -ano }
$updates = TryCmd { wmic qfe list full /format:table }
$firewall = TryCmd { netsh advfirewall show allprofiles }
$users = TryCmd { net user }
$groups = TryCmd { net localgroup }
$logs = TryCmd { wevtutil qe System /c:50 /rd:true /f:text }

$json = @"
{
  "timestamp": "$ts",
  "hostname": "$(Sanitize $env:COMPUTERNAME)",
  "os": "$(Sanitize $($os.Caption))",
  "os_version": "$(Sanitize $($os.Version))",
  "build_number": "$(Sanitize $($os.BuildNumber))",
  "architecture": "$(Sanitize $env:PROCESSOR_ARCHITECTURE)",
  "manufacturer": "$(Sanitize $($cs.Manufacturer))",
  "model": "$(Sanitize $($cs.Model))",

  "running_services_top200": "$(Sanitize $services)",
  "processes_top200": "$(Sanitize $processes)",
  "listening_ports": "$(Sanitize $ports)",
  "installed_updates": "$(Sanitize $updates)",
  "firewall_status": "$(Sanitize $firewall)",
  "local_users": "$(Sanitize $users)",
  "local_groups": "$(Sanitize $groups)",
  "system_logs_tail50": "$(Sanitize $logs)"
}
"@

$json | Set-Content -Encoding UTF8 $out
Write-Host "[INFO] Snapshot written to $out"
