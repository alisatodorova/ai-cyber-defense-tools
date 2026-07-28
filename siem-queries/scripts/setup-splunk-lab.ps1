<#
.SYNOPSIS
  Post-install helper for the local Splunk lab. Mints a REST API token and sets
  SPLUNK_HOST / SPLUNK_TOKEN so the /query command works.

.DESCRIPTION
  Run AFTER Splunk Enterprise is installed and running. Does not require admin;
  it only talks to the Splunk REST API (https://localhost:8089).

  Steps:
    1. Verify the REST endpoint is reachable.
    2. Prompt for the Splunk admin username/password (used once, not stored).
    3. Enable token auth if disabled, then create a token.
    4. Save SPLUNK_HOST / SPLUNK_TOKEN as USER environment variables.
    5. Smoke-test a search against index=botsv3.

.EXAMPLE
  pwsh -File scripts\setup-splunk-lab.ps1
  pwsh -File scripts\setup-splunk-lab.ps1 -SplunkHost https://localhost:8089
#>

[CmdletBinding()]
param(
    [string]$SplunkHost = "https://localhost:8089",
    [string]$TokenAudience = "siem-queries-lab"
)

$ErrorActionPreference = "Stop"

# Works on both Windows PowerShell 5.1 (powershell.exe) and PowerShell 7 (pwsh).
$IsPS7 = $PSVersionTable.PSVersion.Major -ge 6

# Splunk uses a self-signed cert in a lab. On 5.1 there is no -SkipCertificateCheck,
# so accept the self-signed cert process-wide via a validation callback + TLS 1.2.
if (-not $IsPS7) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol = `
        [System.Net.SecurityProtocolType]::Tls12
}

function Invoke-SplunkApi {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers,
        [object]$Body
    )
    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        ErrorAction = "Stop"
    }
    # 5.1 relies on the global callback above; 7 uses the per-call flag.
    if ($IsPS7) { $params.SkipCertificateCheck = $true }
    if ($PSBoundParameters.ContainsKey('Body')) { $params.Body = $Body }
    return Invoke-RestMethod @params
}

Write-Host "==> Splunk lab setup" -ForegroundColor Cyan
Write-Host "    Host: $SplunkHost"

# --- 1. Reachability ---------------------------------------------------------
# Test the management port with a raw TCP connect. The REST endpoints require auth
# (they return 401 unauthenticated), so an HTTP probe would false-negative here.
$uri = [System.Uri]$SplunkHost
$probeHost = $uri.Host
$probePort = if ($uri.Port -gt 0) { $uri.Port } else { 8089 }
$tcpOk = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $iar = $tcp.BeginConnect($probeHost, $probePort, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(8000, $false) -and $tcp.Connected) {
        $tcp.EndConnect($iar); $tcpOk = $true
    }
    $tcp.Close()
} catch { $tcpOk = $false }

if ($tcpOk) {
    Write-Host "[ok] Management port ${probeHost}:${probePort} is reachable." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Cannot reach ${probeHost}:${probePort}." -ForegroundColor Red
    Write-Host "       Splunk running?   & 'C:\Program Files\Splunk\bin\splunk.exe' status" -ForegroundColor Yellow
    Write-Host "       Right port? REST/mgmt is 8089 (HTTPS), NOT the web UI on 8000." -ForegroundColor Yellow
    exit 1
}

# --- 2. Admin credentials (used once) ---------------------------------------
$cred = Get-Credential -Message "Splunk admin login (used once to mint a token; not stored)"
$basic = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes(
        "$($cred.UserName):$($cred.GetNetworkCredential().Password)"))
$authHeader = @{ Authorization = "Basic $basic" }

# --- 3. Enable token auth, then mint a token --------------------------------
Write-Host "==> Ensuring token authentication is enabled..."
try {
    Invoke-SplunkApi -Method POST `
        -Uri "$SplunkHost/services/admin/token-auth/tokens_auth?output_mode=json" `
        -Headers $authHeader `
        -Body @{ disabled = "false" } | Out-Null
    Write-Host "[ok] Token auth enabled." -ForegroundColor Green
} catch {
    # Already enabled or endpoint differs by version - not fatal; token create will confirm.
    Write-Host "[warn] Could not toggle token-auth (may already be on). Continuing." -ForegroundColor Yellow
}

Write-Host "==> Creating REST API token..."
try {
    $tok = Invoke-SplunkApi -Method POST `
        -Uri "$SplunkHost/services/authorization/tokens?output_mode=json" `
        -Headers $authHeader `
        -Body @{
            name     = $cred.UserName
            audience = $TokenAudience
            # No 'expires_on' => long-lived lab token. Add e.g. expires_on='+30d' to limit.
        }
    $token = $tok.entry[0].content.token
    if ([string]::IsNullOrWhiteSpace($token)) { throw "Token field empty in response." }
    Write-Host "[ok] Token created (audience: $TokenAudience)." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Token creation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "       Enable it in Splunk Web: Settings -> Tokens -> Enable Token Authentication." -ForegroundColor Yellow
    exit 1
}

# --- 4. Persist env vars (USER scope) ---------------------------------------
[Environment]::SetEnvironmentVariable("SPLUNK_HOST", $SplunkHost, "User")
[Environment]::SetEnvironmentVariable("SPLUNK_TOKEN", $token, "User")
# Also set for the current session so the smoke test below works immediately.
$env:SPLUNK_HOST = $SplunkHost
$env:SPLUNK_TOKEN = $token
Write-Host "[ok] SPLUNK_HOST / SPLUNK_TOKEN saved to your user environment." -ForegroundColor Green
Write-Host "     (Open a NEW terminal for other tools to see them.)" -ForegroundColor Yellow

# --- 5. Smoke test against BOTS ---------------------------------------------
Write-Host "==> Smoke-testing a search against index=botsv3..."
try {
    $result = Invoke-SplunkApi -Method POST `
        -Uri "$SplunkHost/services/search/jobs/export" `
        -Headers @{ Authorization = "Bearer $token" } `
        -Body @{
            search       = "| tstats count where index=botsv3 by sourcetype"
            earliest_time = "0"
            latest_time  = "now"
            output_mode  = "json"
        }
    if ($result) {
        Write-Host "[ok] Search returned data - botsv3 is queryable." -ForegroundColor Green
    } else {
        Write-Host "[warn] Search ran but returned nothing. Is BOTS v3 loaded? (docs/splunk-lab-setup.md step 2)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[warn] Smoke test failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "       Token/env are set; verify the botsv3 index exists." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Try:  /query queries\lsass-access.txt -15y" -ForegroundColor Cyan
Write-Host "(BOTS data is from 2018 - always pass a wide timerange like -15y.)" -ForegroundColor Cyan
