<#
.SYNOPSIS
  End-to-end verification of the OAuth + MCP flow, including the negative cases.

.DESCRIPTION
  Drives the whole token dance against a running AuthServer and McpServer, then asserts the
  security properties that matter: PKCE enforcement, single-use codes, audience binding,
  per-user isolation, and scope step-up challenges.

  Run this before involving Microsoft 365 Copilot. Debugging OAuth through Copilot is slow and
  the errors it surfaces are vague; everything here fails fast and says why.

.EXAMPLE
  .\smoke-oauth.ps1
  .\smoke-oauth.ps1 -AuthServer https://abc-7029.euw.devtunnels.ms -McpServer https://abc-7071.euw.devtunnels.ms
#>
[CmdletBinding()]
param(
    [string]$AuthServer = 'http://localhost:7029',
    [string]$McpServer = 'http://localhost:7071',
    [string]$ClientId = 'copilot-test-client',
    [string]$ClientSecret = 'copilot-test-secret'
)

$ErrorActionPreference = 'Stop'
$AuthServer = $AuthServer.TrimEnd('/')
$McpServer = $McpServer.TrimEnd('/')
$Resource = "$McpServer/mcp"
$script:Failures = 0

function Write-Section($text) {
    Write-Host ''
    Write-Host "── $text " -NoNewline -ForegroundColor Cyan
    Write-Host ('─' * [Math]::Max(0, 60 - $text.Length)) -ForegroundColor DarkGray
}

function Assert-That($condition, $description, $detail = '') {
    if ($condition) {
        Write-Host '  PASS ' -NoNewline -ForegroundColor Green
        Write-Host $description
    }
    else {
        Write-Host '  FAIL ' -NoNewline -ForegroundColor Red
        Write-Host "$description $detail"
        $script:Failures++
    }
}

function New-PkcePair {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $verifier = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    $hash = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))
    $challenge = [Convert]::ToBase64String($hash).TrimEnd('=').Replace('+', '-').Replace('/', '_')

    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

function Get-AuthorizationCode {
    param($Scope, $Subject, $ResourceUri, $Pkce, $RedirectUri = 'http://localhost:8090/callback')

    $query = @{
        response_type         = 'code'
        client_id             = $ClientId
        redirect_uri          = $RedirectUri
        scope                 = $Scope
        code_challenge        = $Pkce.Challenge
        code_challenge_method = 'S256'
        resource              = $ResourceUri
        state                 = 'smoke-test-state'
    }

    $pairs = $query.GetEnumerator() | ForEach-Object {
        "$($_.Key)=$([Uri]::EscapeDataString($_.Value))"
    }

    # -MaximumRedirection 0 so the 302 to /login is visible rather than followed.
    $authorize = Invoke-WebRequest "$AuthServer/authorize?$($pairs -join '&')" `
        -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue

    $location = $authorize.Headers.Location
    if (-not $location) { throw "No redirect from /authorize (HTTP $($authorize.StatusCode))." }
    if ("$location" -notmatch 'rid=([^&]+)') { throw "Unexpected redirect: $location" }

    $rid = $Matches[1]

    $consent = Invoke-WebRequest "$AuthServer/consent" -Method Post `
        -Body @{ rid = $rid; subject = $Subject; action = 'approve' } `
        -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue

    $callback = "$($consent.Headers.Location)"
    if ($callback -notmatch '[?&]code=([^&]+)') { throw "No code in callback: $callback" }

    [pscustomobject]@{ Code = $Matches[1]; Callback = $callback; RedirectUri = $RedirectUri }
}

function Get-AccessToken {
    param($Scope = 'mcp:tools.read mcp:tools.write', $Subject = 'user-ada', $ResourceUri = $Resource)

    $pkce = New-PkcePair
    $auth = Get-AuthorizationCode -Scope $Scope -Subject $Subject -ResourceUri $ResourceUri -Pkce $pkce

    $response = Invoke-RestMethod "$AuthServer/token" -Method Post -Body @{
        grant_type    = 'authorization_code'
        code          = $auth.Code
        redirect_uri  = $auth.RedirectUri
        code_verifier = $pkce.Verifier
        client_id     = $ClientId
        client_secret = $ClientSecret
    }

    $response
}

function Read-JwtPayload($jwt) {
    $part = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    $part = $part.PadRight($part.Length + ((4 - $part.Length % 4) % 4), '=')
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
}

function Invoke-McpTool {
    param($Token, $Tool, [hashtable]$Arguments = @{})

    $body = @{
        jsonrpc = '2.0'
        id      = 1
        method  = 'tools/call'
        params  = @{ name = $Tool; arguments = $Arguments }
    } | ConvertTo-Json -Depth 10 -Compress

    $headers = @{ Accept = 'application/json, text/event-stream' }
    if ($Token) { $headers['Authorization'] = "Bearer $Token" }

    $response = Invoke-WebRequest "$McpServer/mcp" -Method Post -Body $body `
        -ContentType 'application/json' -Headers $headers -SkipHttpErrorCheck

    # Streamable HTTP replies as SSE, so the JSON sits behind a "data: " prefix.
    $payload = ($response.Content -split "`n" | Where-Object { $_ -like 'data: *' } |
        ForEach-Object { $_.Substring(6) }) -join ''

    [pscustomobject]@{
        StatusCode     = [int]$response.StatusCode
        WwwAuthenticate = "$($response.Headers['WWW-Authenticate'])"
        Result         = if ($payload) { $payload | ConvertFrom-Json } else { $null }
        Raw            = $response.Content
    }
}

# ──────────────────────────────────────────────────────────────────────────────

Write-Host "Auth server : $AuthServer"
Write-Host "MCP server  : $McpServer"
Write-Host "Resource    : $Resource"

Write-Section 'Authorization server metadata (RFC 8414)'

$metadata = Invoke-RestMethod "$AuthServer/.well-known/oauth-authorization-server"
Assert-That ($metadata.issuer -eq $AuthServer) 'issuer matches the configured public URL' "(got $($metadata.issuer))"
Assert-That ([bool]$metadata.registration_endpoint) 'registration_endpoint is advertised (required for DCR)'
Assert-That ($metadata.code_challenge_methods_supported -contains 'S256') 'S256 PKCE is advertised'
Assert-That ($metadata.code_challenge_methods_supported -notcontains 'plain') 'plain PKCE is not advertised'
Assert-That ($metadata.authorization_response_iss_parameter_supported -eq $true) 'RFC 9207 iss parameter is advertised'

$jwks = Invoke-RestMethod "$AuthServer/.well-known/jwks.json"
Assert-That ($jwks.keys.Count -ge 1 -and $jwks.keys[0].kty -eq 'RSA') 'JWKS publishes an RSA signing key'

Write-Section 'Protected resource metadata (RFC 9728)'

$prm = Invoke-RestMethod "$McpServer/.well-known/oauth-protected-resource/mcp"
Assert-That ($prm.resource -eq $Resource) 'resource identifier is the canonical MCP endpoint' "(got $($prm.resource))"
Assert-That ($prm.authorization_servers -contains $AuthServer) 'metadata points at the authorization server'

Write-Section 'Dynamic client registration (RFC 7591)'

$registration = Invoke-RestMethod "$AuthServer/register" -Method Post -ContentType 'application/json' -Body (@{
        client_name   = 'smoke-test client'
        redirect_uris = @('http://localhost:8090/callback')
        grant_types   = @('authorization_code', 'refresh_token')
    } | ConvertTo-Json)

Assert-That ([bool]$registration.client_id) 'DCR returns a client_id'
Assert-That ([bool]$registration.client_secret) 'DCR returns a client_secret (Copilot requires one)'

Write-Section 'Authorization code flow with PKCE'

$token = Get-AccessToken
$claims = Read-JwtPayload $token.access_token

Assert-That ([bool]$token.access_token) 'token endpoint returns an access token'
Assert-That ($claims.aud -eq $Resource) 'token audience is the MCP endpoint' "(got $($claims.aud))"
Assert-That ($claims.iss -eq $AuthServer) 'token issuer is the authorization server' "(got $($claims.iss))"
Assert-That ($claims.sub -eq 'user-ada') 'token subject is the signed-in user'
Assert-That ([bool]$token.refresh_token -eq $false) 'no refresh token without offline_access'

$offline = Get-AccessToken -Scope 'mcp:tools.read offline_access'
Assert-That ([bool]$offline.refresh_token) 'refresh token issued when offline_access is granted'

$refreshed = Invoke-RestMethod "$AuthServer/token" -Method Post -Body @{
    grant_type    = 'refresh_token'
    refresh_token = $offline.refresh_token
    client_id     = $ClientId
    client_secret = $ClientSecret
}
Assert-That ([bool]$refreshed.access_token) 'refresh_token grant returns a new access token'

$reused = Invoke-WebRequest "$AuthServer/token" -Method Post -SkipHttpErrorCheck -Body @{
    grant_type    = 'refresh_token'
    refresh_token = $offline.refresh_token
    client_id     = $ClientId
    client_secret = $ClientSecret
}
Assert-That ($reused.StatusCode -eq 400) 'refresh tokens rotate: the old one stops working'

Write-Section 'Negative cases at the token endpoint'

$pkce = New-PkcePair
$auth = Get-AuthorizationCode -Scope 'mcp:tools.read' -Subject 'user-ada' -ResourceUri $Resource -Pkce $pkce

$first = Invoke-WebRequest "$AuthServer/token" -Method Post -SkipHttpErrorCheck -Body @{
    grant_type = 'authorization_code'; code = $auth.Code; redirect_uri = $auth.RedirectUri
    code_verifier = $pkce.Verifier; client_id = $ClientId; client_secret = $ClientSecret
}
$replay = Invoke-WebRequest "$AuthServer/token" -Method Post -SkipHttpErrorCheck -Body @{
    grant_type = 'authorization_code'; code = $auth.Code; redirect_uri = $auth.RedirectUri
    code_verifier = $pkce.Verifier; client_id = $ClientId; client_secret = $ClientSecret
}
Assert-That ($first.StatusCode -eq 200) 'authorization code redeems once'
Assert-That ($replay.StatusCode -eq 400) 'replaying the same code is rejected'

$pkce2 = New-PkcePair
$auth2 = Get-AuthorizationCode -Scope 'mcp:tools.read' -Subject 'user-ada' -ResourceUri $Resource -Pkce $pkce2
$badVerifier = Invoke-WebRequest "$AuthServer/token" -Method Post -SkipHttpErrorCheck -Body @{
    grant_type = 'authorization_code'; code = $auth2.Code; redirect_uri = $auth2.RedirectUri
    code_verifier = 'not-the-right-verifier-but-long-enough'; client_id = $ClientId; client_secret = $ClientSecret
}
Assert-That ($badVerifier.StatusCode -eq 400) 'a wrong code_verifier is rejected (PKCE enforced)'

$pkce3 = New-PkcePair
$auth3 = Get-AuthorizationCode -Scope 'mcp:tools.read' -Subject 'user-ada' -ResourceUri $Resource -Pkce $pkce3
$badSecret = Invoke-WebRequest "$AuthServer/token" -Method Post -SkipHttpErrorCheck -Body @{
    grant_type = 'authorization_code'; code = $auth3.Code; redirect_uri = $auth3.RedirectUri
    code_verifier = $pkce3.Verifier; client_id = $ClientId; client_secret = 'wrong-secret'
}
Assert-That ($badSecret.StatusCode -eq 401) 'a wrong client secret is rejected'

Write-Section 'Negative cases at the authorize endpoint'

$plain = Invoke-WebRequest "$AuthServer/authorize?response_type=code&client_id=$ClientId&redirect_uri=$([Uri]::EscapeDataString('http://localhost:8090/callback'))&code_challenge=abc&code_challenge_method=plain" `
    -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
Assert-That ("$($plain.Headers.Location)" -like '*error=invalid_request*') 'plain PKCE is refused'

$badRedirect = Invoke-WebRequest "$AuthServer/authorize?response_type=code&client_id=$ClientId&redirect_uri=$([Uri]::EscapeDataString('https://evil.example/cb'))&code_challenge=abc&code_challenge_method=S256" `
    -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
Assert-That ($badRedirect.StatusCode -eq 400) 'an unregistered redirect_uri is refused'

Write-Section 'MCP server authorization'

$anonymous = Invoke-McpTool -Token $null -Tool 'whoami'
Assert-That ($anonymous.StatusCode -eq 401) 'an unauthenticated call is rejected with 401'
Assert-That ($anonymous.WwwAuthenticate -like '*resource_metadata=*') 'the 401 carries a resource_metadata pointer'

$tampered = Invoke-McpTool -Token ($token.access_token.Substring(0, $token.access_token.Length - 1) + 'X') -Tool 'whoami'
Assert-That ($tampered.StatusCode -eq 401) 'a tampered signature is rejected'

Write-Section 'MCP tools'

$whoami = Invoke-McpTool -Token $token.access_token -Tool 'whoami'
$identity = $whoami.Result.result.content[0].text | ConvertFrom-Json
Assert-That ($whoami.StatusCode -eq 200) 'whoami succeeds with a valid token'
Assert-That ($identity.subject -eq 'user-ada') 'the token subject reaches the tool' "(got $($identity.subject))"

$adaTasks = (Invoke-McpTool -Token $token.access_token -Tool 'list_my_tasks').Result.result.content[0].text | ConvertFrom-Json

$graceToken = Get-AccessToken -Subject 'user-grace'
$graceTasks = (Invoke-McpTool -Token $graceToken.access_token -Tool 'list_my_tasks').Result.result.content[0].text | ConvertFrom-Json

Assert-That ($adaTasks.owner -ne $graceTasks.owner) 'two users resolve to different owners'
Assert-That (($adaTasks.tasks.title | Where-Object { $graceTasks.tasks.title -contains $_ }).Count -eq 0) `
    'per-user data is isolated: no overlapping tasks'

$created = Invoke-McpTool -Token $token.access_token -Tool 'create_task' -Arguments @{ title = 'Smoke test task' }
Assert-That ($created.StatusCode -eq 200) 'create_task succeeds with the write scope'

Write-Section 'Scope enforcement and step-up'

$readOnly = Get-AccessToken -Scope 'mcp:tools.read'
$denied = Invoke-McpTool -Token $readOnly.access_token -Tool 'create_task' -Arguments @{ title = 'Should be refused' }

Assert-That ($denied.StatusCode -eq 403) 'create_task without the write scope returns 403'
Assert-That ($denied.WwwAuthenticate -like '*insufficient_scope*') 'the 403 reports insufficient_scope'
Assert-That ($denied.WwwAuthenticate -like '*scope="mcp:tools.write"*') 'the challenge names the scope needed for step-up'

$allowed = Invoke-McpTool -Token $readOnly.access_token -Tool 'list_my_tasks'
Assert-That ($allowed.StatusCode -eq 200) 'a read-scoped token can still call read tools'

$forced = Invoke-McpTool -Token $token.access_token -Tool 'force_unauthorized'
Assert-That ($forced.StatusCode -eq 401) 'force_unauthorized returns 401 for re-auth testing'

Write-Section 'Audience binding'

# Requires "http://localhost:7071/other-resource" in the auth server's AllowedResources.
try {
    $foreign = Get-AccessToken -ResourceUri "$McpServer/other-resource"
    $foreignCall = Invoke-McpTool -Token $foreign.access_token -Tool 'whoami'
    Assert-That ($foreignCall.StatusCode -eq 401) 'a token minted for another resource is rejected'
}
catch {
    Write-Host '  SKIP ' -NoNewline -ForegroundColor Yellow
    Write-Host 'audience test needs an alternate entry in OAuth:AllowedResources'
}

# ──────────────────────────────────────────────────────────────────────────────

Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host 'All checks passed.' -ForegroundColor Green
    exit 0
}

Write-Host "$($script:Failures) check(s) failed." -ForegroundColor Red
exit 1
