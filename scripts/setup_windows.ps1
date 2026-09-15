[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Set-Location $ProjectRoot

if (-not (Test-Path $VenvPython)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.12 -m venv (Join-Path $ProjectRoot ".venv")
    }
    elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv (Join-Path $ProjectRoot ".venv")
    }
    else {
        throw "Python was not found. Install Python 3.11-3.13 and enable Add Python to PATH."
    }
}

# Restore the pip bundled with Python when a previous self-upgrade was interrupted.
# Do not force a network pip self-upgrade: the project does not require it.
& $VenvPython -m ensurepip --upgrade
& $VenvPython -m pip install -r (Join-Path $ProjectRoot "requirements.txt") -r (Join-Path $ProjectRoot "requirements-dev.txt")

Write-Host ""
Write-Host "Environment setup completed: $VenvPython" -ForegroundColor Green
Write-Host "Dependencies do not need to be reinstalled next time. Run scripts\start_all.ps1."
