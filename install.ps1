# BlastRadius Agent — one-command install (Windows PowerShell).
# Run:  .\install.ps1   (or: powershell -ExecutionPolicy Bypass -File install.ps1)
$ErrorActionPreference = "Stop"

Write-Host "🔴 Installing BlastRadius Agent..."

# Check Python 3.11+
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
  Write-Host "Python 3.11+ required — install it first: https://www.python.org/downloads/"
  exit 1
}
$ver = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $ver.Split(".")
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 11)) {
  Write-Host "Python 3.11+ required (found $ver)"
  exit 1
}

# Install from PyPI, fall back to the git repo.
python -m pip install blastradius-agent
if ($LASTEXITCODE -ne 0) {
  Write-Host "[*] PyPI install failed — installing from GitHub..."
  python -m pip install "git+https://github.com/mysterious75/blastradius-agent"
}

Write-Host "✅ BlastRadius installed!"
Write-Host "Run: python -m blastradius.cli.wizard"
