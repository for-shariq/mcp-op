<#
.SYNOPSIS
  Stops both servers, rebuilds, and starts them again in the background.
.DESCRIPTION
  A running server locks its own .dll, so a plain `dotnet build` fails mid-iteration with MSB3027.
  This stops first, then builds, then starts.

  The servers run as `dotnet <Name>.dll` (UseAppHost=false), not as a native .exe, so they still
  start on machines where AppLocker/SRP blocks unsigned executables.
#>
[CmdletBinding()]
param(
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

& "$PSScriptRoot\stop.ps1" -Ports 7029, 7071

if (-not $NoBuild) {
    Write-Host 'Building...' -ForegroundColor Cyan
    dotnet build "$root\McpOp.slnx" --nologo --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
}

Write-Host 'Starting AuthServer (7029) and McpServer (7071)...' -ForegroundColor Cyan

function Start-DotnetApp($name, $dir) {
    $dll = "$root\src\$name\bin\Debug\net10.0\$name.dll"
    if (-not (Test-Path $dll)) { throw "$dll not found. Run without -NoBuild first." }

    # Working directory is the project folder so appsettings*.json and .keys\ resolve correctly.
    Start-Process dotnet -ArgumentList "`"$dll`"" -WorkingDirectory "$root\src\$dir" `
        -Environment @{ ASPNETCORE_ENVIRONMENT = 'Development' } `
        -RedirectStandardOutput "$env:TEMP\mcp-op-$dir.log" -RedirectStandardError "$env:TEMP\mcp-op-$dir.err.log"
}

Start-DotnetApp AuthServer AuthServer
Start-DotnetApp McpServer McpServer

Start-Sleep -Seconds 7

try {
    $health = Invoke-RestMethod 'http://localhost:7071/health' -TimeoutSec 5
    Write-Host "MCP server up.  resource=$($health.resource)" -ForegroundColor Green
    $meta = Invoke-RestMethod 'http://localhost:7029/.well-known/oauth-authorization-server' -TimeoutSec 5
    Write-Host "Auth server up. issuer=$($meta.issuer)" -ForegroundColor Green
}
catch {
    Write-Warning "Servers did not come up cleanly: $_"
    Write-Host "Logs: $env:TEMP\mcp-op-AuthServer*.log and $env:TEMP\mcp-op-McpServer*.log"
    exit 1
}
