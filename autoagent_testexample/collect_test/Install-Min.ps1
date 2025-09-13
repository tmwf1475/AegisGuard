# Install-Min.ps1 — Minimal dependency bootstrap (Windows, no remediation)
Param()

Write-Host "[*] Installing minimal tools if available (winget/choco optional)..." -ForegroundColor Cyan

# Try winget (Win11/Win10 recent)
if (Get-Command winget -ErrorAction SilentlyContinue) {
  try {
    winget install --silent --accept-package-agreements --accept-source-agreements Git.Git 2>$null
  } catch {}
}

# Optional: fallback to choco
if (-not (Get-Command winget -ErrorAction SilentlyContinue) -and (Get-Command choco -ErrorAction SilentlyContinue)) {
  try { choco install -y git } catch {}
}

Write-Host "[*] Done." -ForegroundColor Green
