<#
.SYNOPSIS
  Stops both servers, rebuilds, and starts them again in the background.
.DESCRIPTION
  A running server locks its own .exe, so a plain `dotnet build` fails mid-iteration with MSB3027.
  This stops first, then builds, then starts.
#>
[CmdletBinding()]
param(
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

Write-Host 'Stopping any running servers...' -ForegroundColor Cyan
Get-Process -Name McpServer, AuthServer -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

if (-not $NoBuild) {
    Write-Host 'Building...' -ForegroundColor Cyan
    dotnet build "$root\McpOp.slnx" --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}

Write-Host 'Starting AuthServer (7029) and McpServer (7071)...' -ForegroundColor Cyan
Start-Process dotnet -ArgumentList "run --project `"$root\src\AuthServer\AuthServer.csproj`" --no-build" `
    -WorkingDirectory $root -RedirectStandardOutput "$env:TEMP\mcp-op-auth.log" -RedirectStandardError "$env:TEMP\mcp-op-auth.err.log"
Start-Process dotnet -ArgumentList "run --project `"$root\src\McpServer\McpServer.csproj`" --no-build" `
    -WorkingDirectory $root -RedirectStandardOutput "$env:TEMP\mcp-op-mcp.log" -RedirectStandardError "$env:TEMP\mcp-op-mcp.err.log"

Start-Sleep -Seconds 7

try {
    $health = Invoke-RestMethod 'http://localhost:7071/health' -TimeoutSec 5
    Write-Host "MCP server up.  resource=$($health.resource)" -ForegroundColor Green
    $meta = Invoke-RestMethod 'http://localhost:7029/.well-known/oauth-authorization-server' -TimeoutSec 5
    Write-Host "Auth server up. issuer=$($meta.issuer)" -ForegroundColor Green
}
catch {
    Write-Warning "Servers did not come up cleanly: $_"
    Write-Host "Logs: $env:TEMP\mcp-op-auth.log and $env:TEMP\mcp-op-mcp.log"
    exit 1
}
