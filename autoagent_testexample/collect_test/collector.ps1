# Compatible collector for Windows Server 2008 R2

# Set variables
$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
$hostname = $env:COMPUTERNAME
$ip = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).IPAddress | Where-Object { $_ -ne "127.0.0.1" } | Select-Object -First 1
$os = (Get-WmiObject Win32_OperatingSystem).Caption
$kernel = (Get-WmiObject Win32_OperatingSystem).Version
$arch = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
$user = $env:USERNAME
$uptimeRaw = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
$uptime = (New-TimeSpan -Start $uptimeRaw -End (Get-Date)).ToString()

# CPU & Memory
$cpuLoad = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$mem = Get-WmiObject Win32_OperatingSystem
$memUsage = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)

# Disk Usage
$disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$diskUsage = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)

# Services
$services = Get-WmiObject Win32_Service | Select-Object -First 50 | ForEach-Object {
    @{ pid = $_.ProcessId; name = $_.Name }
}

# Network Connections (netstat fallback)
$netstat = netstat -an | findstr "TCP UDP" | ForEach-Object { $_.Trim() }

# System Logs
$logs = wevtutil qe System /c:30 /f:text /rd:true 2>$null

# Installed hotfixes
$hotfixes = Get-WmiObject Win32_QuickFixEngineering | Select-Object -First 50 | ForEach-Object {
    "$($_.HotFixID) - $($_.Description)"
}

# Installed Software (from registry)
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
    Where-Object { $_.DisplayName } |
    Select-Object -ExpandProperty DisplayName

# Build JSON
$payload = @{
    timestamp = $timestamp
    hostname = $hostname
    ip = $ip
    os = $os
    kernel = $kernel
    arch = $arch
    user = $user
    uptime = $uptime
    cpu_usage = $cpuLoad
    memory_usage = $memUsage
    disk_usage = "$diskUsage"
    services = $services
    network_connections = $netstat
    logs = $logs
    installed_hotfixes = $hotfixes
    installed_software = $software
}

# Export to file
$jsonPath = "$env:TEMP\mcp_payload.json"
$payload | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8

# Compress to .gz using GZipStream workaround
Add-Type -AssemblyName System.IO.Compression.FileSystem
$gzipPath = "$env:TEMP\mcp_payload.json.gz"
if (Test-Path $gzipPath) { Remove-Item $gzipPath }

$sourceStream = [System.IO.File]::OpenRead($jsonPath)
$targetStream = [System.IO.File]::Create($gzipPath)
$gzipStream = New-Object System.IO.Compression.GZipStream($targetStream, [System.IO.Compression.CompressionMode]::Compress)
$sourceStream.CopyTo($gzipStream)
$gzipStream.Close()
$sourceStream.Close()
$targetStream.Close()

# Upload
$uri = "http://140.128.101.238:8000/detection/monitor/snapshot"
try {
    Invoke-RestMethod -Uri $uri -Method Post -Headers @{"Content-Encoding"="gzip"; "Content-Type"="application/json"} -InFile $gzipPath
    Write-Host "[INFO] Upload successful."
} catch {
    Write-Host "[ERROR] Upload failed: $_"
    Copy-Item $jsonPath -Destination "$env:USERPROFILE\Desktop\last_failed_payload.json"
}
