# install.ps1 - Setup environment for MCP Windows collector (Windows Server 2008 R2 version)

Write-Host "Setting up MCP Windows Collector environment..."

# Ensure script is run as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Create log file
$logPath = "$env:ProgramData\mcp_collector.log"
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType File -Force | Out-Null
    Write-Host "Log file created at $logPath"
}

# Optional: Sysinternals Tools
Write-Host "`n[Optional] You can download Sysinternals Suite manually from:"
Write-Host "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"

# Basic notice for missing PSWindowsUpdate module
Write-Host "`nSkipping PowerShell module installation. Not supported on this system."

# Register scheduled task using schtasks.exe
$taskName = "MCP_Collector"
$collectorScript = "$PSScriptRoot\collector.ps1"

if (Test-Path $collectorScript) {
    Write-Host "`nCreating scheduled task to run collector.ps1 every 30 minutes..."

    $escapedScriptPath = $collectorScript -replace '\\', '\\\\'  # escape backslashes for schtasks
    $cmd = "powershell.exe -ExecutionPolicy Bypass -File `"$collectorScript`""

    schtasks /create /tn "$taskName" /tr "$cmd" /sc minute /mo 30 /ru SYSTEM /f | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Scheduled task '$taskName' created successfully."
    } else {
        Write-Host "Failed to create scheduled task." -ForegroundColor Red
    }
} else {
    Write-Host "collector.ps1 not found in current directory. Task not created." -ForegroundColor Red
}

Write-Host "`nMCP Collector environment setup complete."
