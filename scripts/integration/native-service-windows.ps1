$ErrorActionPreference = "Stop"

# This test mutates the native Windows service and Program Files installation.
# It is intentionally restricted to disposable CI runners unless explicitly
# opted in by the caller.
if (($env:CI -ne "true") -and ($env:YUHAIIN_NATIVE_SERVICE_ALLOW_GLOBAL -ne "1")) {
    throw "[native-service-windows] refusing to touch the Windows Service Manager outside CI; set YUHAIIN_NATIVE_SERVICE_ALLOW_GLOBAL=1 to opt in"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cacheRoot = if ($env:YUHAIIN_CACHE_DIR) {
    $env:YUHAIIN_CACHE_DIR
} else {
    Join-Path $env:USERPROFILE ".cache\yuhaiin-rust"
}
$scenarioRoot = if ($env:YUHAIIN_NATIVE_SERVICE_WINDOWS_DIR) {
    $env:YUHAIIN_NATIVE_SERVICE_WINDOWS_DIR
} else {
    Join-Path $cacheRoot "integration\native-service-windows"
}
$runId = "{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmss"), $PID
$runDir = Join-Path $scenarioRoot $runId
$dataDir = Join-Path $runDir "data"
$binary = Join-Path $repoRoot "target\release\yuhaiin.exe"
$installed = $false

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$probe.Start()
$port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
$probe.Stop()
$hostAddress = "127.0.0.1:$port"

function Invoke-Yuhaiin {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $binary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "yuhaiin failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

try {
    Write-Host "[native-service-windows] building release binary in the native runner"
    & cargo build --locked --release -p yuhaiin-runtime --bin yuhaiin --all-features *> (Join-Path $runDir "build.log")
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $binary)) { throw "release binary missing: $binary" }

    Write-Host "[native-service-windows] installing Windows service on $hostAddress"
    $installed = $true
    Invoke-Yuhaiin @("install", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "install.log")
    Invoke-Yuhaiin @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-install.log")
    Invoke-Yuhaiin @("restart", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "restart.log")
    Invoke-Yuhaiin @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-restart.log")

    Write-Host "[native-service-windows] applying a staged update and checking rollback"
    $staged = Join-Path $runDir "staged-yuhaiin.exe"
    Copy-Item -LiteralPath $binary -Destination $staged -Force
    Invoke-Yuhaiin @("update-helper", "C:\Program Files\yuhaiin\yuhaiin.exe", $staged) *> (Join-Path $runDir "update.log")
    Invoke-Yuhaiin @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-update.log")
    Invoke-Yuhaiin @("rollback", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "rollback.log")
    Invoke-Yuhaiin @("health", "--host", $hostAddress, "--path", $dataDir) *> (Join-Path $runDir "health-rollback.log")

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
