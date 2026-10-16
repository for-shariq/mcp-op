<#
.SYNOPSIS
  Creates (or reuses) a dev tunnel exposing both servers, writes the public URLs into
  configuration, and starts hosting.

.DESCRIPTION
  Microsoft 365 Copilot can only reach a public HTTPS endpoint, so both services need tunnelling.
  One tunnel with two ports gives each service its own hostname, which keeps issuer and audience
  genuinely separate rather than merely nominally so.

  The public URLs feed the token issuer, the token audience, and the resource metadata document,
  so this script writes them into both appsettings.Development.json files. A tunnel URL that
  disagrees with configuration is the single most common cause of 401s in this rig.

  After running this, restart the servers so they pick up the new URLs, then update the
  Teams developer portal OAuth registration to match.

.EXAMPLE
  .\start-tunnel.ps1
  .\start-tunnel.ps1 -TunnelId my-mcp-op -SkipConfigUpdate
#>
[CmdletBinding()]
param(
    [string]$TunnelId = 'mcp-op',
    [int]$AuthPort = 7029,
    [int]$McpPort = 7071,
    [switch]$SkipConfigUpdate,
    [switch]$NoHost
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command devtunnel -ErrorAction SilentlyContinue)) {
    Write-Error @'
devtunnel is not installed. Install it with:

    winget install Microsoft.devtunnel

then sign in with:

    devtunnel user login
'@
    exit 1
}

Write-Host "Ensuring tunnel '$TunnelId' exists..." -ForegroundColor Cyan

# --allow-anonymous matters: Copilot and Teams reach these URLs without any tunnel credentials.
devtunnel create $TunnelId --allow-anonymous 2>&1 | Out-String | Write-Verbose
devtunnel port create $TunnelId -p $AuthPort 2>&1 | Out-String | Write-Verbose
devtunnel port create $TunnelId -p $McpPort 2>&1 | Out-String | Write-Verbose

# This devtunnel CLI version never exposes portUri via JSON (show or port show), so
# build the URL ourselves: https://<full-tunnel-id>-<port>.devtunnels.ms, where
# <full-tunnel-id> is the service-decorated id (e.g. "mcp-op.inc1") returned by `show`.
$details = devtunnel show $TunnelId --json | ConvertFrom-Json
$fullTunnelId = $details.tunnel.tunnelId

if (-not $fullTunnelId) {
    Write-Error "Could not resolve tunnel id. 'devtunnel show $TunnelId --json' returned:`n$($details | ConvertTo-Json -Depth 6)"
    exit 1
}

$authUrl = "https://$fullTunnelId-$AuthPort.devtunnels.ms"
$mcpUrl = "https://$fullTunnelId-$McpPort.devtunnels.ms"

$authUrl = $authUrl.TrimEnd('/')
$mcpUrl = $mcpUrl.TrimEnd('/')

Write-Host ''
Write-Host 'Public URLs' -ForegroundColor Green
Write-Host "  Auth server : $authUrl"
Write-Host "  MCP server  : $mcpUrl"
Write-Host "  MCP endpoint: $mcpUrl/mcp    <- plugin manifest url, and Teams 'Base URL'"
Write-Host ''

if (-not $SkipConfigUpdate) {
    $authConfigPath = Join-Path $root 'src\AuthServer\appsettings.Development.json'
    $mcpConfigPath = Join-Path $root 'src\McpServer\appsettings.Development.json'

    $authConfig = Get-Content $authConfigPath -Raw | ConvertFrom-Json
    $authConfig.OAuth.PublicUrl = $authUrl
    $authConfig.OAuth.DefaultResource = "$mcpUrl/mcp"
    $authConfig.OAuth.AllowedResources = @("$mcpUrl/mcp", "$mcpUrl/other-resource")
    $authConfig | ConvertTo-Json -Depth 10 | Set-Content $authConfigPath -Encoding utf8

    $mcpConfig = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json
    $mcpConfig.Mcp.PublicUrl = $mcpUrl
    $mcpConfig.Mcp.AuthServerUrl = $authUrl
    $mcpConfig | ConvertTo-Json -Depth 10 | Set-Content $mcpConfigPath -Encoding utf8

    Write-Host 'Updated appsettings.Development.json for both services.' -ForegroundColor Green
    Write-Host 'Restart the servers (scripts\restart.ps1) so they pick up the new URLs.' -ForegroundColor Yellow
    Write-Host ''
}

Write-Host 'Remember to update the OAuth client registration in the Teams developer portal:' -ForegroundColor Yellow
Write-Host "  Base URL             : $mcpUrl/mcp"
Write-Host "  Authorization endpoint: $authUrl/authorize"
Write-Host "  Token endpoint        : $authUrl/token"
Write-Host "  Refresh endpoint      : $authUrl/token"
Write-Host '  Restrict usage by app : Any Teams app   <- binding to an app ID causes 404s on every tool call'
Write-Host ''

if ($NoHost) {
    Write-Host "Not hosting. Start it yourself with: devtunnel host $TunnelId"
    exit 0
}

Write-Host "Hosting tunnel '$TunnelId' (Ctrl+C to stop)..." -ForegroundColor Cyan
devtunnel host $TunnelId
