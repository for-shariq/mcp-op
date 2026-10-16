<#
.SYNOPSIS
  Validates and packages the Copilot Cowork plugin in cowork-plugin\ into an uploadable .zip.

.DESCRIPTION
  1. Reads cowork-plugin\plugin.env (MCP server URL, OAuth registration ID).
  2. Copies cowork-plugin\appPackage to a staging folder and substitutes ${{...}} placeholders.
  3. Validates the package against the Cowork platform rules and the Teams manifest schema.
  4. Writes cowork-plugin\build\<name>.zip with every entry at the package root.

  Works on Windows PowerShell 5.1 and PowerShell 7. Schema validation needs PowerShell 7
  (Test-Json) and is skipped with a notice on 5.1; every other check runs on both.

  Compress-Archive is deliberately NOT used: on Windows PowerShell 5.1 it writes entry names with
  backslashes, which the upload validator can reject. Entries here always use forward slashes.

.PARAMETER EnvFile
  Build values. Defaults to cowork-plugin\plugin.env.

.PARAMETER SkipSchema
  Skip the manifest JSON schema check (it downloads the schema on first use).

.EXAMPLE
  .\build-cowork-plugin.ps1
  .\build-cowork-plugin.ps1 -EnvFile .\cowork-plugin\plugin.prod.env
#>
[CmdletBinding()]
param(
    [string]$EnvFile,
    [switch]$SkipSchema
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pluginRoot = Join-Path $root 'cowork-plugin'
$source = Join-Path $pluginRoot 'appPackage'
$stage = Join-Path $pluginRoot 'build\stage'
$outDir = Join-Path $pluginRoot 'build'
if (-not $EnvFile) { $EnvFile = Join-Path $pluginRoot 'plugin.env' }

$script:Errors = New-Object System.Collections.Generic.List[string]
function Add-Problem([string]$message) { $script:Errors.Add($message) }

function Read-EnvFile([string]$path) {
    if (-not (Test-Path $path)) { throw "Env file not found: $path" }
    $values = @{}
    foreach ($line in Get-Content $path) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $key, $value = $line.Split('=', 2)
        $values[$key.Trim()] = $value.Trim()
    }
    $values
}

function Get-PngSize([string]$path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $signature = [byte[]](0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    for ($i = 0; $i -lt 8; $i++) { if ($bytes[$i] -ne $signature[$i]) { return $null } }
    # IHDR width and height are big-endian uint32 at offsets 16 and 20.
    $width = ($bytes[16] * 16777216) + ($bytes[17] * 65536) + ($bytes[18] * 256) + $bytes[19]
    $height = ($bytes[20] * 16777216) + ($bytes[21] * 65536) + ($bytes[22] * 256) + $bytes[23]
    @{ Width = $width; Height = $height }
}

# ---------------------------------------------------------------------------------------------
Write-Host 'Reading build values...' -ForegroundColor Cyan
$config = Read-EnvFile $EnvFile

$mcpUrl = "$($config['MCP_SERVER_URL'])".TrimEnd('/')
$referenceId = "$($config['OAUTH_REFERENCE_ID'])"

if ($mcpUrl -notmatch '^https://') { Add-Problem "MCP_SERVER_URL must be an https URL (got '$mcpUrl')." }
if ($mcpUrl -match 'REPLACE-ME') { Add-Problem 'MCP_SERVER_URL is still the REPLACE-ME placeholder. Set it to your dev tunnel URL.' }
if ($mcpUrl -match '/mcp$') { Add-Problem 'MCP_SERVER_URL must not end in /mcp; the manifest appends it.' }

if ($script:Errors.Count -gt 0) {
    $script:Errors | ForEach-Object { Write-Host "  ERROR $_" -ForegroundColor Red }
    exit 1
}

$authMode = if ($referenceId) { "OAuthPluginVault (reference $referenceId)" } else { 'none in manifest - Cowork dynamic client registration' }
Write-Host "  MCP server : $mcpUrl/mcp"
Write-Host "  Auth       : $authMode"

# ---------------------------------------------------------------------------------------------
Write-Host 'Staging package...' -ForegroundColor Cyan
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item (Join-Path $source '*') $stage -Recurse -Force

$manifestPath = Join-Path $stage 'manifest.json'
$manifestText = (Get-Content $manifestPath -Raw).Replace('${{MCP_SERVER_URL}}', $mcpUrl)
$manifest = $manifestText | ConvertFrom-Json

# Blank registration ID means "let Cowork register the client": drop the authorization object.
# The schema forbids a referenceId for type None, and an empty one is invalid for the others.
foreach ($connector in @($manifest.agentConnectors)) {
    $server = $connector.toolSource.remoteMcpServer
    if ($referenceId) {
        $server.authorization.referenceId = $referenceId
    }
    else {
        $server.PSObject.Properties.Remove('authorization')
    }
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 20), $utf8NoBom)

# ---------------------------------------------------------------------------------------------
Write-Host 'Validating...' -ForegroundColor Cyan

foreach ($field in 'manifestVersion', 'version', 'id', 'developer', 'name', 'description', 'icons', 'accentColor') {
    if (-not $manifest.PSObject.Properties[$field]) { Add-Problem "manifest.json is missing required field '$field'." }
}

if ($manifest.id -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Problem "manifest id '$($manifest.id)' is not a GUID." }
if ($manifest.name.short.Length -gt 30) { Add-Problem "name.short is $($manifest.name.short.Length) chars; the limit is 30." }
if ($manifest.description.short.Length -gt 80) { Add-Problem "description.short is $($manifest.description.short.Length) chars; the limit is 80." }

# Icons.
foreach ($icon in @(@('color.png', 192), @('outline.png', 32))) {
    $path = Join-Path $stage $icon[0]
    if (-not (Test-Path $path)) { Add-Problem "$($icon[0]) is missing."; continue }
    $size = Get-PngSize $path
    if (-not $size) { Add-Problem "$($icon[0]) is not a PNG." }
    elseif ($size.Width -ne $icon[1] -or $size.Height -ne $icon[1]) {
        Add-Problem "$($icon[0]) is $($size.Width)x$($size.Height); it must be $($icon[1])x$($icon[1])."
    }
}

# Skills (ASKILL-M001..M003, P001..P008).
$skills = @($manifest.agentSkills)
if ($skills.Count -gt 20) { Add-Problem "ASKILL-M002: $($skills.Count) skills; the limit is 20." }
$seenFolders = @{}
foreach ($entry in $skills) {
    $folder = "$($entry.folder)"
    if (-not $folder) { Add-Problem 'ASKILL-M001: an agentSkills entry has no folder.'; continue }
    if ($folder.Length -gt 256) { Add-Problem "ASKILL-M003: folder path is longer than 256 chars: $folder" }
    if ($seenFolders[$folder]) { Add-Problem "ASKILL-P008: duplicate folder $folder" }
    $seenFolders[$folder] = $true

    $dir = Join-Path $stage $folder
    $leaf = Split-Path $folder -Leaf
    if (-not (Test-Path $dir)) { Add-Problem "ASKILL-P001: folder $folder is not in the package."; continue }

    $skillFile = Join-Path $dir 'SKILL.md'
    if (-not (Test-Path $skillFile)) { Add-Problem "ASKILL-P002: $folder has no SKILL.md."; continue }

    $content = Get-Content $skillFile -Raw
    if ($content -notmatch '(?s)^\s*---\r?\n(.*?)\r?\n---') { Add-Problem "ASKILL-P003: $folder\SKILL.md has no YAML frontmatter between --- lines."; continue }
    $frontmatter = $Matches[1]

    if ($frontmatter -notmatch '(?m)^name:\s*(\S+)\s*$') { Add-Problem "ASKILL-P004: $folder\SKILL.md frontmatter has no name."; $skillName = $null }
    else { $skillName = $Matches[1].Trim('"', "'") }
    if ($frontmatter -notmatch '(?m)^description:') { Add-Problem "ASKILL-P005: $folder\SKILL.md frontmatter has no description." }

    if ($skillName) {
        if ($skillName -ne $leaf) { Add-Problem "ASKILL-P006: name '$skillName' does not match folder '$leaf'." }
        if ($skillName -cnotmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $skillName.Length -gt 64) { Add-Problem "ASKILL-P007: name '$skillName' must be kebab-case, 1-64 chars." }
    }

    # Companion files.
    $companions = @(Get-ChildItem $dir -Recurse -File | Where-Object { $_.Name -ne 'SKILL.md' })
    if ($companions.Count -gt 20) { Add-Problem "$folder has $($companions.Count) companion files; the limit is 20." }
    if (($companions | Measure-Object Length -Sum).Sum -gt 10MB) { Add-Problem "$folder companion files exceed 10 MB in total." }
    foreach ($file in $companions) {
        if ($file.Length -gt 5MB) { Add-Problem "$($file.Name) is larger than 5 MB." }
        if ($file.Name.StartsWith('.')) { Add-Problem "$($file.Name) is a hidden file." }
        if ($file.BaseName -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { Add-Problem "$($file.Name) uses a Windows reserved name." }
        if ($file.Name -notmatch '^[A-Za-z0-9._ !-]+$') { Add-Problem "$($file.Name) has characters outside the allowed set." }
    }
}

# Connectors.
$connectors = @($manifest.agentConnectors)
if ($connectors.Count -gt 10) { Add-Problem "$($connectors.Count) connectors; the limit is 10." }
$seenIds = @{}
foreach ($connector in $connectors) {
    if (-not $connector.id -or -not $connector.displayName) { Add-Problem 'A connector needs an id and a displayName.' }
    if ($connector.id.Length -gt 64) { Add-Problem "Connector id '$($connector.id)' is longer than 64 chars." }
    if ($seenIds[$connector.id]) { Add-Problem "Duplicate connector id '$($connector.id)'." }
    $seenIds[$connector.id] = $true

    $server = $connector.toolSource.remoteMcpServer
    if (-not $server) { Add-Problem "Connector '$($connector.id)' needs toolSource.remoteMcpServer."; continue }
    if ($server.mcpServerUrl -notmatch '^[Hh][Tt][Tt][Pp][Ss]://') { Add-Problem "mcpServerUrl must be https: $($server.mcpServerUrl)" }

    if ($server.PSObject.Properties['mcpToolDescription']) {
        $toolFile = Join-Path $stage $server.mcpToolDescription.file
        if (-not (Test-Path $toolFile)) { Add-Problem "mcpToolDescription file '$($server.mcpToolDescription.file)' is not in the package." }
    }

    $auth = $server.PSObject.Properties['authorization']
    if ($auth) {
        $type = $auth.Value.type
        $ref = $auth.Value.PSObject.Properties['referenceId']
        if ($type -eq 'None' -and $ref) { Add-Problem 'authorization.referenceId must not be present when type is None.' }
        if ($type -ne 'None' -and (-not $ref -or -not $ref.Value)) { Add-Problem "authorization.referenceId is required for type $type." }
    }
}

# Manifest JSON schema. Needs Test-Json, which only PowerShell 7 has.
if (-not $SkipSchema) {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host '  (schema check skipped: needs PowerShell 7)' -ForegroundColor DarkGray
    }
    else {
        $version = $manifest.manifestVersion
        $schemaPath = Join-Path $outDir "schema-$version.json"
        try {
            if (-not (Test-Path $schemaPath)) {
                Invoke-WebRequest "https://developer.microsoft.com/json-schemas/teams/v$version/MicrosoftTeams.schema.json" -OutFile $schemaPath
            }
            $problems = $null
            $ok = Test-Json -Json (Get-Content $manifestPath -Raw) -SchemaFile $schemaPath -ErrorVariable problems -ErrorAction SilentlyContinue
            $unparseable = $problems | Where-Object { $_.Exception.Message -match 'Cannot parse the JSON schema' }
            if ($unparseable) {
                # Test-Json cannot read this schema. That is a tooling limit, not a manifest error.
                Write-Host '  (schema check skipped: Test-Json cannot parse the Teams schema; run `wiqd plugin validate --mode deep` or the Developer Portal validator)' -ForegroundColor DarkGray
            }
            elseif (-not $ok) {
                foreach ($p in $problems) { Add-Problem "schema v${version}: $($p.Exception.Message)" }
            }
            else { Write-Host "  manifest matches the v$version schema" -ForegroundColor DarkGray }
        }
        catch { Write-Host "  (schema check skipped: $($_.Exception.Message))" -ForegroundColor DarkGray }
    }
}

if ($script:Errors.Count -gt 0) {
    Write-Host ''
    Write-Host "$($script:Errors.Count) problem(s) found:" -ForegroundColor Red
    $script:Errors | ForEach-Object { Write-Host "  ERROR $_" -ForegroundColor Red }
    exit 1
}

# ---------------------------------------------------------------------------------------------
Write-Host 'Packaging...' -ForegroundColor Cyan
$zipName = ('{0}-{1}.zip' -f ($manifest.name.short -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLower(), $manifest.version)
$zipPath = Join-Path $outDir $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

# ZipFile is in System.IO.Compression.FileSystem, which Windows PowerShell 5.1 does not load by default.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $prefix = (Resolve-Path $stage).Path.TrimEnd('\') + '\'
    foreach ($file in Get-ChildItem $stage -Recurse -File) {
        $entryName = $file.FullName.Substring($prefix.Length).Replace('\', '/')
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal)
    }
}
finally { $zip.Dispose() }

Write-Host ''
Write-Host "Built $zipPath" -ForegroundColor Green
$check = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try { $check.Entries | ForEach-Object { Write-Host "  $($_.FullName)  ($($_.Length) bytes)" } }
finally { $check.Dispose() }

Write-Host ''
Write-Host 'Next: upload it. See docs\pluginsteps.md, "Install and test".' -ForegroundColor Yellow
