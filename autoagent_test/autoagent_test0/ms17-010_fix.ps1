# Import required modules
Import-Module -Name BitsTransfer
Import-Module -Name ServerManager

# Function to check if the system is vulnerable
function Check-Vulnerability {
    $vulnerable = Get-WindowsFeature -Name SMB1 | Where-Object {$_.InstallState -eq 'Available'}
    if ($vulnerable) {
        Write-Host "System is vulnerable to MS17-010"
        return $true
    } else {
        Write-Host "System is not vulnerable to MS17-010"
        return $false
    }
}

# Function to download and install the patch
function Install-Patch {
    $patch = 'Windows8.1-KB3192404-x64.exe' # Update with actual patch name for Windows Server 2008
    $downloadPath = 'C:\Patches'
    if (!(Test-Path -Path $downloadPath)) {
        New-Item -ItemType Directory -Path $downloadPath
    }
    $patchPath = Join-Path -Path $downloadPath -ChildPath $patch
    Write-Host "Downloading and installing patch..."
    Start-BitsTransfer -DisplayName $patch -SaveAs $patchPath -Priority High
    Write-Host "Patch installation completed"
}

# Function to restart the system if necessary
function Restart-System {
    Write-Host "Restarting the system..."
    Restart-Computer
}

# Main script
Write-Host "MS17-010 patching script"

# Check if the system is vulnerable
if (Check-Vulnerability) {
    # Download and install the patch
    Install-Patch
    
    # Restart the system if necessary
    Restart-System
} else {
    Write-Host "No patch needed, system is not vulnerable"
}

Write-Host "Script completed"

