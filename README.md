# mcp-op — Copilot MCP plugin + self-hosted OAuth 2.1 test rig

A self-contained rig for exercising the Microsoft 365 Copilot MCP-plugin authentication path end to
end, without using Microsoft Entra ID as the identity provider.

Three pieces:

| Project | Role | Port |
| --- | --- | --- |
| [src/AuthServer/](src/AuthServer/) | OAuth 2.1 authorization server — issues, refreshes and validates tokens; registers clients statically and via RFC 7591 DCR | 7029 |
| [src/McpServer/](src/McpServer/) | Remote MCP server acting as an OAuth resource server, exposing five auth-aware test tools | 7071 |
| [agent/](agent/) | Declarative agent app package whose plugin manifest points at the MCP server | — |

**Why a hand-rolled authorization server.** Microsoft Entra ID publishes no RFC 7591 registration
endpoint, so dynamic client registration has nothing to register against, and the
`agentConnectors` node has no Entra authorization type. Owning the AS also makes every leg of the
flow — consent, PKCE, audience binding, scope step-up — observable while debugging.

## Quick start (local, no tunnel)

```powershell
.\scripts\restart.ps1      # build and start both servers
.\scripts\smoke-oauth.ps1  # 36 assertions across the whole flow
```

`smoke-oauth.ps1` should report **All checks passed**. It covers RFC 8414/9728 metadata, DCR,
the authorization code flow with PKCE, refresh token rotation, code replay, audience binding,
per-user isolation, and the `insufficient_scope` step-up challenge.

## The test tools

Each tool exists to prove one property of the auth path rather than to be useful.

| Tool | Proves |
| --- | --- |
| `whoami` | The validated token's identity reaches tool code. The primary smoke test. |
| `get_token_info` | Audience and issuer binding are correct — returns `aud`, `iss`, `jti`, `exp`. |
| `list_my_tasks` | Per-user data isolation; keyed on the `sub` claim. Requires `mcp:tools.read`. |
| `create_task` | Scope enforcement and Copilot's confirmation card. Requires `mcp:tools.write`. |
| `force_unauthorized` | The client's re-authentication path. Always returns 401 with a challenge. |

Three test identities (`user-ada`, `user-grace`, `user-alan`) with distinct seed data. There are no
passwords: the login page is a picker, so you can switch users instantly and watch isolation hold.

## Architecture notes worth knowing before you change anything

**The resource identifier is the MCP endpoint, not the host.** `http://localhost:7071/mcp` is the
canonical resource URI, used as the token `aud`, the `resource` in protected resource metadata, and
the Base URL in the Teams OAuth registration. Those three must agree or every call 401s.

**Audience validation is the security boundary.** [src/McpServer/Program.cs](src/McpServer/Program.cs)
rejects tokens not minted for this resource. That is what prevents a token issued for another
service being replayed here; the MCP spec makes it a `MUST`.

**Scope enforcement has to be middleware.** The MCP spec requires insufficient scope to surface as
HTTP 403 with a `WWW-Authenticate` challenge, because that is what drives a client's step-up
authorization. By the time a tool method runs, the JSON-RPC response is already being composed, so
an exception there becomes a tool error with a 200 status and no challenge — the client has nothing
to step up from. Hence
[ScopeEnforcementMiddleware](src/McpServer/Auth/ScopeEnforcementMiddleware.cs), which peeks at
`tools/call` and short-circuits. It deliberately lets `initialize` and `tools/list` through, or
discovery breaks.

**Audience fallback when `resource` is absent.** On Copilot's static registration path, Teams drives
token acquisition from the auth config's configured endpoints and does not necessarily send an
RFC 8707 `resource` parameter. `TokenService.ResolveResource` therefore falls back to
`OAuth:DefaultResource`. Without that fallback the MCP server's audience check rejects every token
Copilot presents.

**`MapInboundClaims = false` is load-bearing.** Without it the JWT handler rewrites `sub` to a long
WS-* claim URI and every `FindFirstValue("sub")` in a tool returns null.

## Exposing to Copilot

Copilot can only reach a public HTTPS endpoint.

```powershell
winget install Microsoft.devtunnel
devtunnel user login
.\scripts\start-tunnel.ps1     # creates the tunnel, rewrites both appsettings, hosts
.\scripts\restart.ps1          # pick up the new URLs
```

The tunnel URLs feed the token issuer, the token audience, and the resource metadata document.
**A tunnel URL that disagrees with configuration is the most common cause of 401s in this rig.**
After a tunnel change you must also update the Teams developer portal registration.

Verify through the tunnel before involving Copilot:

```powershell
.\scripts\smoke-oauth.ps1 -AuthServer https://<id>-7029.<region>.devtunnels.ms `
                          -McpServer  https://<id>-7071.<region>.devtunnels.ms
```

Then point [MCP Inspector](https://github.com/modelcontextprotocol/inspector) at the MCP tunnel URL —
it drives discovery, DCR, PKCE and the resource parameter, and reports spec violations far more
clearly than Copilot will:

```
npx @modelcontextprotocol/inspector
```

## Wiring up the declarative agent

Scaffold with Microsoft 365 Agents Toolkit **6.12.0+**: *Create a New Agent/App → Declarative Agent
→ Add an Action → Start with an MCP Server*, entering `<mcp-tunnel-url>/mcp`.

The files in [agent/](agent/) are a working reference for what the toolkit produces. Agents Toolkit
will regenerate them and fill the `${{...}}` placeholders from `agent/env/.env.local`.

**Static registration first.** Choose *OAuth (with static registration)* and supply
`copilot-test-client` / `copilot-test-secret` (seeded in
[ClientStore.cs](src/AuthServer/Services/ClientStore.cs)) with scopes
`mcp:tools.read mcp:tools.write offline_access`. The toolkit reads the authorize/token/refresh
endpoints from the AS's well-known document and writes the auth config ID into `ai-plugin.json`.

**Then switch to DCR.** Re-provision choosing *OAuth (with dynamic registration)*. Nothing in the
manifest changes but the auth config ID: `auth.type` stays `OAuthPluginVault`. Copilot walks
`/.well-known/oauth-protected-resource/mcp` → `/.well-known/oauth-authorization-server` →
`POST /register`. This is the leg that validates the RFC 7591 implementation, and the reason this
rig doesn't use Entra.

### Gotchas that produce misleading failures

- **Restrict usage by app → "Any Teams app."** Binding to a specific Teams app ID makes
  provisioning *succeed* and then every tool call return **404**. In `m365agents.yml` this is
  `applicableToApps: AnyApp` — and keep the `appId` field, because the provisioning driver
  validates it unconditionally even though `AnyApp` makes it inert.
- **Base URL must match** the `url` in the plugin manifest's MCP server spec object.
- **`oauth/register` never rewrites.** If `configurationId` has a value it silently does nothing.
  Use `oauth/update` to change one; the Teams developer portal is the only place that can delete one.
- **Don't use `AzureKeyVault`** in `agentConnectors` — it exists only in the `devPreview` schema and
  fails validation against numbered schema versions.
- **Scope consent isn't verified at provisioning time.** A scope nobody can consent to provisions
  fine, then fails at runtime with *Need admin approval*.
- Clear a stored token via **Chat settings → Agents** in Copilot to retest sign-in.

## Not production ready

In-memory stores, no real credentials, no key rotation, no rate limiting, and the dev tunnel
terminates TLS. All of that needs addressing before anything resembling this ships; none of it is
needed to validate the flow.

The `/debug/clients` and `/debug/revoke-user/{subject}` endpoints on the AS, and the
`get_token_info` and `force_unauthorized` tools, are diagnostics — remove them before this becomes
anything real.

## Reference

- [Configure OAuth 2.0 authentication](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-oauth)
- [Configure dynamic client registration](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-dynamic-client-registration)
- [Build a plugin for a declarative agent from an MCP server](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/build-mcp-plugins)
- [Plugin manifest schema 2.4](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-manifest-2.4)
- [Dynamic tool discovery](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-dynamic-tool-discovery)
- [MCP specification — Authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [MCP C# SDK `ProtectedMcpServer` sample](https://github.com/modelcontextprotocol/csharp-sdk/tree/main/samples/ProtectedMcpServer)
