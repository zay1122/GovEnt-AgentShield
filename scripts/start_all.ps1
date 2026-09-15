[CmdletBinding()]
param(
    [int]$ApiPort = 8080,
    [int]$DashboardPort = 8501
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Candidates = @(
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe"),
    (Join-Path (Split-Path $ProjectRoot -Parent) ".venv\Scripts\python.exe")
)
$Python = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Python) {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) {
        throw "Python was not found. First run: powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1"
    }
    $Python = $PythonCommand.Source
}

& $Python -c "import flask, streamlit" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Flask or Streamlit is missing. First run scripts\setup_windows.ps1."
}

$ApiArgs = @("src\api.py")
$DashboardArgs = @(
    "-m", "streamlit", "run", "dashboard\app.py",
    "--server.address", "127.0.0.1",
    "--server.port", "$DashboardPort"
    "--server.headless", "true"
)
Write-Host "Starting API: http://127.0.0.1:$ApiPort" -ForegroundColor Cyan
$PreviousHost = $env:AGENTSHIELD_HOST
$PreviousPort = $env:AGENTSHIELD_PORT
$env:AGENTSHIELD_HOST = "127.0.0.1"
$env:AGENTSHIELD_PORT = "$ApiPort"
Start-Process -FilePath $Python -ArgumentList $ApiArgs -WorkingDirectory $ProjectRoot
$env:AGENTSHIELD_HOST = $PreviousHost
$env:AGENTSHIELD_PORT = $PreviousPort

$Healthy = $false
for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
    try {
        $Health = Invoke-RestMethod "http://127.0.0.1:$ApiPort/health" -TimeoutSec 1
        if ($Health.status -eq "ok") {
            $Healthy = $true
            break
        }
    }
    catch {
        Start-Sleep -Milliseconds 300
    }
}
if (-not $Healthy) {
    throw "API startup failed. Run python src\api.py to inspect the error."
}

Write-Host "Starting Dashboard: http://127.0.0.1:$DashboardPort" -ForegroundColor Cyan
Start-Process -FilePath $Python -ArgumentList $DashboardArgs -WorkingDirectory $ProjectRoot
Start-Sleep -Seconds 2
Start-Process "http://127.0.0.1:$DashboardPort"

Write-Host "Startup completed. Select a case on the default dashboard and run it." -ForegroundColor Green
