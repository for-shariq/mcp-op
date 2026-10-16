# Expected results

Use this to judge whether a response from the MCP OAuth Test server is correct.

## Test identities

| Subject | Name | Username |
| --- | --- | --- |
| `user-ada` | Ada Lovelace | ada@contoso.test |
| `user-grace` | Grace Hopper | grace@contoso.test |
| `user-alan` | Alan Turing | alan@contoso.test |

## Per tool

| Tool | Expected when working | Failure meaning |
| --- | --- | --- |
| `whoami` | `subject` is one of the identities above and `grantedScopes` includes `mcp:tools.read` | No `sub` claim means the server cannot identify the caller |
| `get_token_info` | `audience` ends in `/mcp`; `issuer` is the authorization server URL | An audience that is not the MCP endpoint would have been rejected with 401 before the tool ran |
| `list_my_tasks` | Two seeded tasks for the user; users never share tasks | The same tasks for two different users means identity is not reaching the data layer |
| `create_task` | `created: true` with a new `id` | `insufficient_scope` means the token lacks `mcp:tools.write` |
| `force_unauthorized` | Always fails with an authentication error | If it succeeds, the server's challenge handling is broken |

## Seeded tasks

| User | Tasks |
| --- | --- |
| Ada | Review the analytical engine spec; Finish the Bernoulli number notes |
| Grace | Debug the Mark II relay; Write the A-0 compiler docs |
| Alan | Draft the imitation game paper; Review Bombe rotor wiring |
