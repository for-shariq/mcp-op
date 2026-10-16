---
name: mcp-oauth-test
description: |
  Diagnoses OAuth 2.0 sign-in and access for the MCP OAuth Test server.
  Use when the user asks "who am I signed in as", "what tasks do I have", "add a task",
  "show my access token details", "what scopes do I have", or "test the sign-in / re-authentication path".
license: MIT
metadata:
  author: mcp-op test rig
  version: "1.0"
---

# MCP OAuth Test

Calls the tools of the **MCP OAuth Test Server** connector to verify that Copilot Cowork signs the user in with OAuth 2.0 and that the signed-in identity reaches the server. Every tool result is real data from the server; never invent identities, tasks or token values.

## Tools

| Tool | Use it to |
| --- | --- |
| `whoami` | Report who the user is signed in as: subject, name, username, department, granted scopes. |
| `get_token_info` | Report the access token's issuer, audience, client ID, scopes and expiry. |
| `list_my_tasks` | List the signed-in user's tasks. Each user only ever sees their own. |
| `create_task` | Add a task for the signed-in user. Changes state. |
| `force_unauthorized` | Deliberately fail with a 401 so the sign-in recovery path can be observed. |

## Workflow

1. **Identity questions** ("who am I", "what scopes do I have"): call `whoami` and report `subject`, `name`, `userName` and `grantedScopes` exactly as returned.
2. **Task questions** ("what tasks do I have"): call `list_my_tasks`. Present the tasks as a short list with id, title and status. State the owner returned by the tool.
3. **Adding a task**: confirm the title with the user, then call `create_task` with that title. Report the new task id. Do not call it speculatively.
4. **Token questions** ("what is my token audience", "when does it expire"): call `get_token_info` and report issuer, audience, scopes and expiry. Never print or ask for the raw token.
5. **Re-authentication test**: only when the user explicitly asks to test sign-in recovery, call `force_unauthorized`, then tell the user what happened and whether Cowork asked them to sign in again.

## Error handling

Report tool errors **verbatim**, including any scope or authentication detail. Authentication errors are the diagnostic here; paraphrasing loses the information.

- `insufficient_scope` naming `mcp:tools.write`: the user's token can read but not write. Say so and name the missing scope.
- A 401 or an `invalid_token` error: the sign-in is missing or expired. Say so; do not guess at the cause.
- Any other error: quote it and stop. Do not retry in a loop.

See [reference](references/test-matrix.md) for the expected result of each call.
