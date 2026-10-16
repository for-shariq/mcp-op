<#
.SYNOPSIS
  Stops the AuthServer and McpServer and frees their ports.

.DESCRIPTION
  Three passes, because a server can be left behind in more than one way:
    1. dotnet.exe processes running AuthServer.dll / McpServer.dll (the normal case).
    2. Legacy AuthServer.exe / McpServer.exe apphost processes from before UseAppHost was disabled.
    3. Anything still listening on the ports: a hung process, or a server that fell back to the
       default port 5000 because it was started without appsettings.json.

  Pass 3 kills whatever owns the port, so it only touches processes on this rig's ports. Use
  -WhatIf to see what would be stopped without stopping it.

.EXAMPLE
  .\stop.ps1
  .\stop.ps1 -WhatIf
  .\stop.ps1 -Ports 7029,7071,5000,5001
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int[]]$Ports = @(7029, 7071, 5000)
)

$stopped = [System.Collections.Generic.HashSet[int]]::new()

function Stop-Target($processId, $reason) {
    if ($processId -le 4 -or $stopped.Contains($processId)) { return }

    $name = (Get-Process -Id $processId -ErrorAction SilentlyContinue).ProcessName
    if (-not $name) { return }

    if ($PSCmdlet.ShouldProcess("PID $processId ($name)", "Stop")) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        Write-Host "  stopped PID $processId ($name) - $reason" -ForegroundColor Yellow
    }
    [void]$stopped.Add($processId)
}

Write-Host 'Stopping servers...' -ForegroundColor Cyan

# 1. dotnet.exe hosting our dlls. Match the command line: the process name is just "dotnet".
Get-CimInstance Win32_Process -Filter "Name = 'dotnet.exe'" |
    Where-Object { $_.CommandLine -match '(AuthServer|McpServer)\.dll' } |
    ForEach-Object { Stop-Target $_.ProcessId 'dotnet host' }

# 2. Legacy native apphosts.
Get-Process -Name AuthServer, McpServer -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Target $_.Id 'legacy exe' }

# 3. Whatever still holds the ports.
foreach ($port in $Ports) {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Target $_.OwningProcess "listening on :$port" }
}

if ($stopped.Count -eq 0) {
    Write-Host '  nothing was running.' -ForegroundColor DarkGray
}

if ($WhatIfPreference) { return }

Start-Sleep -Milliseconds 800

$stillBusy = foreach ($port in $Ports) {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { [pscustomobject]@{ Port = $port; Pid = $_.OwningProcess } }
}

if ($stillBusy) {
    Write-Warning 'Some ports are still in use (may need an elevated shell if owned by another user):'
    $stillBusy | Format-Table | Out-String | Write-Host
    exit 1
}

Write-Host "Ports free: $($Ports -join ', ')" -ForegroundColor Green
