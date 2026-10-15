using System.Net;
using System.Text;
using AuthServer.Services;

namespace AuthServer.Endpoints;

/// <summary>
/// The sign-in and consent screens. Plain server-rendered HTML with no assets, so the pages work
/// inside the Copilot sign-in popup without any static file hosting.
/// </summary>
internal static class Pages
{
    public static string Login(string requestId, string clientName, IReadOnlyList<TestUser> users)
    {
        var buttons = new StringBuilder();

        foreach (var user in users)
        {
            buttons.Append($"""
                <button type="submit" name="subject" value="{E(user.Subject)}" class="user">
                  <span class="avatar">{E(Initials(user.Name))}</span>
                  <span class="who">
                    <strong>{E(user.Name)}</strong>
                    <small>{E(user.UserName)} &middot; {E(user.Department)}</small>
                  </span>
                </button>
                """);
        }

        return Shell("Sign in", $"""
            <h1>Choose a test identity</h1>
            <p class="sub"><strong>{E(clientName)}</strong> wants you to sign in.</p>
            <form method="post" action="/login">
              <input type="hidden" name="rid" value="{E(requestId)}" />
              {buttons}
            </form>
            <p class="note">This is a test authorization server. There are no passwords &mdash; pick
            any identity to continue.</p>
            """);
    }

    public static string Consent(string requestId, TestUser user, PendingAuthRequest request, string clientName)
    {
        var items = new StringBuilder();

        foreach (var scope in request.Scopes)
        {
            items.Append($"""
                <li><code>{E(scope)}</code><span>{E(Scopes.Describe(scope))}</span></li>
                """);
        }

        return Shell("Consent", $"""
            <h1>Allow access?</h1>
            <p class="sub">
              <strong>{E(clientName)}</strong> is requesting access on behalf of
              <strong>{E(user.Name)}</strong>.
            </p>
            <ul class="scopes">{items}</ul>
            <dl class="meta">
              <dt>Resource (token audience)</dt><dd><code>{E(request.Resource)}</code></dd>
              <dt>Signed in as</dt><dd>{E(user.UserName)}</dd>
            </dl>
            <form method="post" action="/consent" class="actions">
              <input type="hidden" name="rid" value="{E(requestId)}" />
              <input type="hidden" name="subject" value="{E(user.Subject)}" />
              <button type="submit" name="action" value="deny" class="secondary">Deny</button>
              <button type="submit" name="action" value="approve" class="primary">Allow</button>
            </form>
            """);
    }

    public static string Message(string title, string body) =>
        Shell(title, $"<h1>{E(title)}</h1><p class=\"sub\">{E(body)}</p>");

    private static string Initials(string name)
    {
        var parts = name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2
            ? string.Concat(parts[0][0], parts[^1][0])
            : name.Length > 0 ? name[0].ToString() : "?";
    }

    private static string E(string value) => WebUtility.HtmlEncode(value);

    private static string Shell(string title, string body) => $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>{{E(title)}} &middot; mcp-op test IdP</title>
          <style>
            :root { color-scheme: light dark; }
            * { box-sizing: border-box; }
            body {
              font: 15px/1.5 "Segoe UI", system-ui, sans-serif;
              margin: 0; min-height: 100vh;
              display: grid; place-items: center;
              background: light-dark(#f3f2f1, #1b1a19);
              color: light-dark(#201f1e, #f3f2f1);
              padding: 24px;
            }
            .card {
              background: light-dark(#fff, #292827);
              border: 1px solid light-dark(#e1dfdd, #3b3a39);
              border-radius: 8px; padding: 32px; width: 100%; max-width: 420px;
              box-shadow: 0 2px 8px rgb(0 0 0 / 12%);
            }
            h1 { font-size: 20px; margin: 0 0 4px; font-weight: 600; }
            .sub { margin: 0 0 20px; color: light-dark(#605e5c, #c8c6c4); }
            .note { font-size: 13px; color: light-dark(#605e5c, #a19f9d); margin: 20px 0 0; }
            button { font: inherit; cursor: pointer; border-radius: 4px; }
            .user {
              display: flex; align-items: center; gap: 12px; width: 100%;
              padding: 10px 12px; margin-bottom: 8px; text-align: left;
              background: transparent; color: inherit;
              border: 1px solid light-dark(#e1dfdd, #3b3a39);
            }
            .user:hover { background: light-dark(#f3f2f1, #3b3a39); }
            .avatar {
              display: grid; place-items: center; flex: 0 0 36px; height: 36px;
              border-radius: 50%; background: #0078d4; color: #fff;
              font-size: 13px; font-weight: 600;
            }
            .who { display: flex; flex-direction: column; }
            .who small { color: light-dark(#605e5c, #a19f9d); }
            .scopes { list-style: none; padding: 0; margin: 0 0 20px; }
            .scopes li {
              display: flex; flex-direction: column; gap: 2px;
              padding: 10px 0; border-top: 1px solid light-dark(#edebe9, #3b3a39);
            }
            .scopes code { font-size: 13px; color: #0078d4; }
            .scopes span { font-size: 13px; color: light-dark(#605e5c, #c8c6c4); }
            .meta { margin: 0 0 20px; font-size: 13px; }
            .meta dt { color: light-dark(#605e5c, #a19f9d); margin-top: 8px; }
            .meta dd { margin: 2px 0 0; }
            .meta code { word-break: break-all; }
            .actions { display: flex; gap: 8px; justify-content: flex-end; }
            .primary { background: #0078d4; color: #fff; border: 1px solid #0078d4; padding: 8px 20px; }
            .primary:hover { background: #106ebe; }
            .secondary {
              background: transparent; color: inherit; padding: 8px 20px;
              border: 1px solid light-dark(#8a8886, #605e5c);
            }
          </style>
        </head>
        <body><main class="card">{{body}}</main></body>
        </html>
        """;
}
