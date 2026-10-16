# Creating a Copilot Cowork plugin with an authenticated MCP connector

This is the repeatable procedure for building a Cowork plugin that calls an OAuth 2.0 protected MCP
server. The working example is [cowork-plugin/](../cowork-plugin/), which targets the test server in
[src/McpServer/](../src/McpServer/). To make a new plugin, copy that folder and follow section 3.

A Cowork plugin is **not** the same package as the declarative agent in [agent/](../agent/). Both
authenticate the same way, but the manifest and package layout differ:

| | Declarative agent plugin ([agent/](../agent/)) | Cowork plugin ([cowork-plugin/](../cowork-plugin/)) |
| --- | --- | --- |
| Manifest | `declarativeAgent.json` + `ai-plugin.json` | One `manifest.json` with `agentSkills[]` and `agentConnectors[]` |
| Tools | `runtimes[]` in `ai-plugin.json` | `agentConnectors[].toolSource.remoteMcpServer` |
| Behaviour | `instructions` in the agent manifest | `SKILL.md` files |
| Auth reference | `auth.reference_id` | `authorization.referenceId` |

## 1. What goes in the package

```
<plugin>.zip                       every entry at the root, forward-slash paths
|-- manifest.json                  Microsoft 365 app manifest (1.29)
|-- color.png                      192x192 full-colour icon
|-- outline.png                    32x32 single-colour icon
`-- skills/
    `-- <skill-name>/              folder name MUST equal the SKILL.md name
        |-- SKILL.md
        `-- references/            optional companion files
```

Limits: 20 skills and 10 connectors per package; 20 companion files per skill, 5 MB each and
10 MB total; connector tool calls should finish in under 30 seconds. Custom plugins are not
supported in Cowork on mobile.

## 2. Prerequisites

| Need | Notes |
| --- | --- |
| Microsoft 365 tenant with Copilot and Cowork | Custom app upload must be allowed for your account |
| A public HTTPS MCP server | Streamable HTTP, TLS 1.2+. For local work use a dev tunnel (section 7) |
| An OAuth 2.0 authorization server | Here: [src/AuthServer/](../src/AuthServer/) |
| Node.js, for the Agents Toolkit CLI | `npm install -g @microsoft/m365agentstoolkit-cli`, then `atk auth login` |
| PowerShell 7 (recommended) | The build script also runs on 5.1, but skips the schema step there |

## 3. Create a new plugin

1. **Copy the template.**
   ```powershell
   Copy-Item cowork-plugin cowork-plugin-contoso -Recurse
   ```
   [build-cowork-plugin.ps1](../scripts/build-cowork-plugin.ps1) reads `cowork-plugin\`. Either work in
   that folder directly, or edit the `$pluginRoot` line in a copy of the script.

2. **Give it a new app ID.** In `appPackage/manifest.json`, replace `id` with a new GUID
   (`[guid]::NewGuid()`). Keep it **stable across versions**: a new GUID is a different app.
   Bump `version` on every upload.

3. **Rename the skill.** Folder name, `SKILL.md` `name:` and the manifest `agentSkills[].folder`
   must all agree. The name is kebab-case: lowercase letters, digits and single hyphens, 1-64 chars.
   The mismatch between folder and `name:` is the most common cause of skill failures.

4. **Edit `manifest.json`.**

   | Field | Limit |
   | --- | --- |
   | `name.short` | 30 chars |
   | `description.short` | 80 chars |
   | `agentConnectors[].id` | 64 chars, unique in the manifest |
   | `agentConnectors[].displayName` | 128 chars |
   | `agentConnectors[].description` | 4000 chars |

   Leave `${{MCP_SERVER_URL}}` and `${{OAUTH_REFERENCE_ID}}` in place; the build fills them in.

   The v1.29 schema is strict (`additionalProperties: false`). Adding a field it doesn't define,
   such as `packageName`, makes the upload fail.

5. **Write `SKILL.md`.** Frontmatter needs `name` and `description`. Put real trigger phrases in the
   description ("who am I signed in as", not "identity tools"), because that is what makes Cowork
   pick the skill. In the body, **name the connector's tools explicitly** ("call `whoami`"); the
   agent links skills to connector tools at runtime from those names. Tell the skill to report tool
   errors verbatim.

6. **Replace the icons** with your own at exactly 192x192 and 32x32.

## 4. Authentication

Pick one. Both end with the user signing in once, and neither puts a secret in the package.

### Option A: static client, `OAuthPluginVault` (works in Cowork and Copilot Chat)

1. **Register a client on your authorization server.** For this repo, add an entry under
   `OAuth:ExtraClients` in [appsettings.Development.json](../src/AuthServer/appsettings.Development.json)
   and restart. One client per consumer keeps secrets independently rotatable.
   ```json
   { "ClientId": "cowork-plugin-client", "ClientSecret": "<new secret>",
     "ClientName": "Cowork plugin",
     "RedirectUris": ["https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect"] }
   ```
   The redirect URI is fixed by the platform and is the same for every plugin.

2. **Register it in the Teams developer portal.** Open <https://dev.teams.microsoft.com/tools>, then
   **Tools > OAuth client registration > New**:

   | Field | Value |
   | --- | --- |
   | Registration name | anything descriptive |
   | Base URL | `https://<host>/mcp`, exactly the manifest's `mcpServerUrl` |
   | Restrict usage by org | **Any Microsoft 365 organization** if the plugin must work across tenants; **My organization only** for dev |
   | Restrict usage by app | **Any Teams app** (see warning) |
   | Client ID / secret | from step 1 |
   | Authorization endpoint | `https://<auth-host>/authorize` |
   | Token endpoint | `https://<auth-host>/token` |
   | Refresh endpoint | `https://<auth-host>/token` |
   | Scope | `mcp:tools.read mcp:tools.write offline_access` |
   | PKCE | enabled (leave on) |

   > **Warning.** Binding the registration to a specific Teams app ID makes provisioning succeed and
   > then every tool call return **404**, because Copilot doesn't resolve that ID when calling an
   > MCP server. Always choose **Any Teams app**.

3. **Copy the registration ID** the portal gives you (labelled *OAuth client registration ID*) into
   `OAUTH_REFERENCE_ID` in `cowork-plugin/plugin.env`. It is not a secret.

### Option B: dynamic client registration (Cowork only)

If your authorization server supports RFC 7591, **leave `OAUTH_REFERENCE_ID` blank.** The build then
omits the `authorization` object and Cowork registers a client for the plugin itself. Requirements:

- the MCP server serves protected resource metadata (RFC 9728) and returns it in the 401 challenge;
- the authorization server publishes `registration_endpoint` (RFC 8414);
- registration **must return a `client_secret`**; secretless DCR is not supported yet.

Omitting `authorization` works in Cowork but **not in Copilot Chat**. If the plugin must also work
in Chat, use Option A. Microsoft Entra ID has no RFC 7591 endpoint, so DCR is never available for an
Entra-protected server.

`ApiKeyPluginVault` is not supported in Cowork yet.

## 5. Prepare the MCP server

- **Annotate every tool.** Cowork asks for confirmation when `readOnlyHint` is `false` or
  `destructiveHint` is `true`, and treats tools with **no annotations as destructive**. Mark safe
  reads `ReadOnly = true` and give each tool a `Title` (shown on the prompt). Done in
  [TestTools.cs](../src/McpServer/Tools/TestTools.cs). Confirmation for non-Microsoft servers is
  rolling out progressively, so set the hints now.
- **Describe every parameter.** The agent reads parameter descriptions to fill arguments.
- **Return structured JSON** the agent can summarise.
- **Return 401 for missing or invalid tokens and 403 + `insufficient_scope` for missing scope**,
  both with `WWW-Authenticate` and `resource_metadata`. Done in
  [ScopeEnforcementMiddleware.cs](../src/McpServer/Auth/ScopeEnforcementMiddleware.cs).
- **Validate token audience.** Reject tokens not minted for your MCP endpoint.
- **Recognising Cowork** (optional): match, case-insensitively and by *prefix*, `copilot-cowork` in
  the `User-Agent` header (every request) or `clientInfo.name` (the `initialize` request only).
  Never match the exact `copilot-cowork/1.0`; the version will change.
- **Tools are discovered dynamically** from `tools/list`, so adding a tool needs no republish. This
  plugin therefore has no `mcpToolDescription`.

## 6. Build and validate

1. Set `cowork-plugin/plugin.env`:
   ```
   MCP_SERVER_URL=https://<id>-7071.<region>.devtunnels.ms   # no trailing slash, no /mcp
   OAUTH_REFERENCE_ID=<registration ID, or blank for DCR>
   ```
2. Build:
   ```powershell
   .\scripts\build-cowork-plugin.ps1
   ```
   It writes `cowork-plugin/build/<name>-<version>.zip`, and refuses to build if any rule below fails.

| Code | Rule |
| --- | --- |
| ASKILL-M001 / M002 / M003 | each skill entry needs a `folder`; at most 20 skills; path at most 256 chars |
| ASKILL-P001 / P002 | the folder is in the zip and contains `SKILL.md` |
| ASKILL-P003 / P004 / P005 | valid YAML frontmatter with `name` and `description` |
| ASKILL-P006 / P007 | `name` equals the folder name and is kebab-case |
| ASKILL-P008 | no duplicate `folder` values |
| Connector | `id` and `displayName` required and unique; `mcpServerUrl` is https; `referenceId` required unless the type is `None`, and forbidden when it is `None` |
| Companion files | at most 20, 5 MB each, 10 MB total; relative paths only; no `..`, hidden files or Windows reserved names |

For the manifest schema check use PowerShell 7 or `wiqd plugin validate --mode deep`. The Teams
schema is at `https://developer.microsoft.com/json-schemas/teams/v1.29/MicrosoftTeams.schema.json`.

## 7. Expose the servers

Cowork can only reach a public HTTPS URL. See the root [README](../README.md) for the full tunnel
setup. Cowork-specific points:

```powershell
.\scripts\start-tunnel.ps1                 # creates the tunnel, rewrites appsettings, hosts
.\scripts\restart.ps1                      # restart so the servers pick up the new URLs
```

- `devtunnel port create <tunnel> -p <port> --protocol http`. **Not `https`**: that flag describes the
  *local* service, and `https` against a plain-HTTP server makes every tunnelled request return 502.
- On macOS a server bound to `0.0.0.0` returns 502 because the tunnel dials IPv6 `localhost` first;
  bind to `::` instead. (Kestrel on Windows serves `localhost` on both.)
- The AS `PublicUrl` and the MCP server's public URL must match the tunnel exactly, because they
  become the token issuer and audience.
- Before involving Cowork, run `.\scripts\smoke-oauth.ps1 -AuthServer <tunnel> -McpServer <tunnel>`.

## 8. Install and test

**Personal sideload (fastest):**
```powershell
atk auth login
atk install --file-path .\cowork-plugin\build\mcp-oauth-test-1.0.0.zip --scope Personal
```
It prints a `TitleId` and `AppId`; keep them to update or uninstall.

**Tenant-wide:** M365 admin center > **Manage apps** > **Upload custom app** > **...** >
**Add agent**, then upload the zip. The plugin appears under **Cowork > Sources & Skills > Plugins >
Discover**.

**Using wiqd instead** (preview): `wiqd plugin create`, `add skill`, `add connector`, `validate`,
`provision`, `package`, `share`. It scaffolds the package but **does not scaffold connector
authentication yet**, so you still add `authorization` to the manifest by hand as in section 4.
`wiqd plugin share` puts the plugin in **Shared with me**, not **Discover**.

**Verify:**
1. In Cowork, ask: *Who am I signed in as?* Expect a **sign-in** prompt for the connector.
2. Sign in on the authorization server's page (pick a test user, approve).
3. Expect `whoami` output with the chosen user's subject and scopes.
4. Ask for the user's tasks; switch to another test user and confirm the lists differ.
5. Ask to add a task; expect a confirmation prompt first.
6. Sign out via **Chat settings > Agents** and confirm sign-in is requested again.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Every tool call returns **404** after provisioning succeeds | Registration bound to a specific Teams app ID | Re-create it with **Any Teams app** |
| Upload fails with `Property '<x>' has not been defined...` | Field not in the strict manifest schema | Remove it |
| Sign-in succeeds but tool calls fail with 401 | Token audience doesn't match the MCP endpoint, or the tunnel URL changed | Check `get_token_info`'s `audience`; align `PublicUrl` and the registration Base URL |
| Sign-in popup never completes | A `Cross-Origin-Opener-Policy: same-origin` header in the redirect chain breaks `window.opener` | Remove that header from the sign-in pages |
| `Need admin approval` at runtime | A scope no one can consent to; provisioning doesn't check | Fix the scope list |
| 502 on every tunnelled request | Port created with `--protocol https` | Recreate it with `--protocol http` |
| Certificate name mismatch locally | Wrong tunnel URL, or a TLS-inspecting proxy | `smoke-oauth.ps1` prints the certificate it received |
| `oauth/register` changes nothing | It never rewrites an existing config | Use `oauth/update`; delete only in the developer portal |
| Plugin missing from **Discover** | Shared with `wiqd share`, or not uploaded by an admin | Admin center upload |

## 10. Known gaps in this guide

- **Not tested in a live tenant.** The package builds and its manifest validates against the v1.29
  schema (0 errors), but I could not install it into Cowork from here.
- **Manifest 1.28 vs 1.29.** Microsoft's Cowork article says 1.28 *requires* `mcpToolDescription` while
  the schema's `required` list shows 1.29 needs only `mcpServerUrl`. This plugin uses 1.29. If you
  must use 1.28, add `mcpToolDescription: { "file": "tools/<name>.json" }` holding the `tools/list`
  result, and include that file in the zip.
- **Cowork redirect URI.** Microsoft documents the Teams redirect URI for plugins generally and says
  Cowork follows the same model; there is no Cowork-specific page.
- A Microsoft Q&A thread describes a Cowork connector that authenticates but whose tool calls then
  fail. It is an unresolved single report; if you see it, check the MCP server log for what token
  arrived.

## References

- [Build plugins for Copilot Cowork](https://learn.microsoft.com/en-us/microsoft-365/copilot/cowork/cowork-plugin-development)
- [Configure OAuth 2.0 authentication](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-oauth)
- [Configure authentication for MCP and API plugins](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication)
- [Configure dynamic client registration](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-dynamic-client-registration)
- [Register MCP servers as agent connectors](https://learn.microsoft.com/en-us/microsoftteams/platform/m365-apps/agent-connectors)
- [Upload your app to Teams](https://learn.microsoft.com/en-us/microsoftteams/platform/concepts/deploy-and-publish/apps-upload)
- [Microsoft 365 Agents Toolkit CLI](https://learn.microsoft.com/en-us/microsoftteams/platform/toolkit/microsoft-365-agents-toolkit-cli)
