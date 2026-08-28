$ErrorActionPreference = "Stop"

# This test mutates the native Windows service and Program Files installation.
# It is intentionally restricted to disposable CI runners unless explicitly
# opted in by the caller.
if (($env:CI -ne "true") -and ($env:DORADUS_NATIVE_SERVICE_ALLOW_GLOBAL -ne "1")) {
    throw "[native-service-windows] refusing to touch the Windows Service Manager outside CI; set DORADUS_NATIVE_SERVICE_ALLOW_GLOBAL=1 to opt in"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cacheRoot = if ($env:DORADUS_CACHE_DIR) {
    $env:DORADUS_CACHE_DIR
} else {
    Join-Path $repoRoot ".cache\doradus"
}
$scenarioRoot = if ($env:DORADUS_NATIVE_SERVICE_WINDOWS_DIR) {
    $env:DORADUS_NATIVE_SERVICE_WINDOWS_DIR
} else {
    Join-Path $cacheRoot "integration\native-service-windows"
}
$runId = "{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmss"), $PID
$runDir = Join-Path $scenarioRoot $runId
$dataDir = Join-Path $runDir "data"
$binary = Join-Path $repoRoot "target\release\doradus.exe"
$installed = $false

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$probe.Start()
$port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
$probe.Stop()
$hostAddress = "127.0.0.1:$port"

function Invoke-Doradus {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $binary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "doradus failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

try {
    Write-Host "[native-service-windows] building release binary in the native runner"
    & cargo build --locked --release -p doradus-api --bin doradus --all-features *> (Join-Path $runDir "build.log")
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $binary)) { throw "release binary missing: $binary" }

    Write-Host "[native-service-windows] installing Windows service on $hostAddress"
    $installed = $true
    Invoke-Doradus @("install", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "install.log")
    Invoke-Doradus @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-install.log")
    Invoke-Doradus @("restart", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "restart.log")
    Invoke-Doradus @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-restart.log")

    Write-Host "[native-service-windows] applying a staged update and checking rollback"
    $staged = Join-Path $runDir "staged-doradus.exe"
    Copy-Item -LiteralPath $binary -Destination $staged -Force
    Invoke-Doradus @("update-helper", "C:\Program Files\doradus\doradus.exe", $staged) *> (Join-Path $runDir "update.log")
    Invoke-Doradus @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-update.log")
    Invoke-Doradus @("rollback", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "rollback.log")
    Invoke-Doradus @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-rollback.log")

    Write-Host "[native-service-windows] passed; logs=$runDir"
} finally {
    if ($installed -and (Test-Path -LiteralPath $binary)) {
        try {
            & $binary uninstall *> (Join-Path $runDir "uninstall.log")
        } catch {
            Write-Warning "Windows service cleanup failed: $($_.Exception.Message)"
        }
    }
}
