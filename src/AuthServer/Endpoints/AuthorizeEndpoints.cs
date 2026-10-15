using AuthServer.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace AuthServer.Endpoints;

/// <summary>
/// The authorization code leg: /authorize parks the request, /login picks a test identity,
/// /consent grants scopes and issues the code.
/// </summary>
public static class AuthorizeEndpoints
{
    public static void MapAuthorizeEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/authorize", (
            HttpContext http,
            ClientStore clients,
            AuthCodeStore codes,
            TokenService tokens,
            IOptions<AuthServerOptions> options,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("Authorize");
            var q = http.Request.Query;

            var clientId = q["client_id"].ToString();
            var redirectUri = q["redirect_uri"].ToString();
            var state = q["state"].ToString();

            // Before the client and redirect URI are validated there is nowhere safe to redirect
            // errors to, so these two failures render directly instead.
            var client = clients.Find(clientId);
            if (client is null)
            {
                return DirectError("invalid_client", "Unknown client_id: " + clientId);
            }

            if (string.IsNullOrEmpty(redirectUri))
            {
                // A single registered URI is unambiguous, so default to it; otherwise demand one.
                if (client.RedirectUris.Count == 1)
                {
                    redirectUri = client.RedirectUris[0];
                }
                else
                {
                    return DirectError("invalid_request", "redirect_uri is required.");
                }
            }

            if (!client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
            {
                logger.LogWarning(
                    "Rejected redirect_uri {RedirectUri} for client {ClientId}", redirectUri, clientId);

                return DirectError(
                    "invalid_request", "redirect_uri is not registered for this client: " + redirectUri);
            }

            // From here errors go back to the client as a redirect, per OAuth 2.1.
            var issuer = options.Value.PublicUrl.TrimEnd('/');

            if (q["response_type"].ToString() != "code")
            {
                return RedirectError(redirectUri, "unsupported_response_type",
                    "Only response_type=code is supported.", state, issuer);
            }

            var codeChallenge = q["code_challenge"].ToString();
            var challengeMethod = q["code_challenge_method"].ToString();

            if (string.IsNullOrEmpty(codeChallenge))
            {
                return RedirectError(redirectUri, "invalid_request",
                    "code_challenge is required: this server mandates PKCE.", state, issuer);
            }

            // Reject plain outright so there is no downgrade path.
            if (!string.Equals(challengeMethod, "S256", StringComparison.Ordinal))
            {
                return RedirectError(redirectUri, "invalid_request",
                    "code_challenge_method must be S256.", state, issuer);
            }

            string resource;
            try
            {
                resource = tokens.ResolveResource(q["resource"].ToString());
            }
            catch (InvalidResourceException ex)
            {
                return RedirectError(redirectUri, "invalid_target", ex.Message, state, issuer);
            }

            var requested = Scopes.Parse(q["scope"].ToString());
            var granted = requested.Length == 0 ? Scopes.Default : Scopes.Filter(requested);

            if (requested.Length > 0 && granted.Length == 0)
            {
                return RedirectError(redirectUri, "invalid_scope",
                    "None of the requested scopes are supported. Supported: "
                        + string.Join(' ', Scopes.Supported),
                    state, issuer);
            }

            var pending = codes.Park(new PendingAuthRequest
            {
                RequestId = ClientStore.RandomToken(16),
                ClientId = client.ClientId,
                RedirectUri = redirectUri,
                Scopes = granted,
                State = string.IsNullOrEmpty(state) ? null : state,
                CodeChallenge = codeChallenge,
                Resource = resource,
            });

            logger.LogInformation(
                "Parked authorize request {RequestId} for client {ClientId}, resource {Resource}, scopes [{Scopes}]",
                pending.RequestId, client.ClientId, resource, string.Join(' ', granted));

            return Results.Redirect("/login?rid=" + pending.RequestId);
        });

        app.MapGet("/login", (string? rid, AuthCodeStore codes, ClientStore clients, TestUserStore users) =>
        {
            var pending = codes.GetPending(rid);
            if (pending is null)
            {
                return ExpiredPage();
            }

            var client = clients.Find(pending.ClientId);
            return Results.Content(
                Pages.Login(rid!, client?.ClientName ?? pending.ClientId, users.All), "text/html");
        });

        app.MapPost("/login", async (
            HttpContext http, AuthCodeStore codes, ClientStore clients, TestUserStore users) =>
        {
            var form = await http.Request.ReadFormAsync();
            var rid = form["rid"].ToString();
            var subject = form["subject"].ToString();

            var pending = codes.GetPending(rid);
            if (pending is null)
            {
                return ExpiredPage();
            }

            var user = users.Find(subject);
            if (user is null)
            {
                return DirectError("invalid_request", "Unknown user.");
            }

            var client = clients.Find(pending.ClientId);
            return Results.Content(
                Pages.Consent(rid, user, pending, client?.ClientName ?? pending.ClientId), "text/html");
        });

        app.MapPost("/consent", async (
            HttpContext http,
            AuthCodeStore codes,
            TestUserStore users,
            IOptions<AuthServerOptions> options,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("Consent");
            var form = await http.Request.ReadFormAsync();

            var rid = form["rid"].ToString();
            var subject = form["subject"].ToString();
            var approved = form["action"].ToString() == "approve";

            var pending = codes.GetPending(rid);
            if (pending is null)
            {
                return ExpiredPage();
            }

            var issuer = options.Value.PublicUrl.TrimEnd('/');
            codes.RemovePending(rid);

            if (!approved)
            {
                logger.LogInformation("User denied consent for request {RequestId}", rid);
                return RedirectError(pending.RedirectUri, "access_denied",
                    "The user denied the request.", pending.State, issuer);
            }

            var user = users.Find(subject);
            if (user is null)
            {
                return DirectError("invalid_request", "Unknown user.");
            }

            var code = codes.IssueCode(pending, user.Subject);
            logger.LogInformation("Issued code for {Subject} on request {RequestId}", user.Subject, rid);

            var parameters = new Dictionary<string, string?>
            {
                ["code"] = code.Code,
                // RFC 9207: lets the client detect a mix-up attack before it posts the code.
                ["iss"] = issuer,
            };

            if (pending.State is not null)
            {
                parameters["state"] = pending.State;
            }

            return Results.Redirect(QueryHelpers.AddQueryString(pending.RedirectUri, parameters));
        });
    }

    private static IResult DirectError(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: 400);

    private static IResult RedirectError(
        string redirectUri, string error, string description, string? state, string issuer)
    {
        var parameters = new Dictionary<string, string?>
        {
            ["error"] = error,
            ["error_description"] = description,
            ["iss"] = issuer,
        };

        if (!string.IsNullOrEmpty(state))
        {
            parameters["state"] = state;
        }

        return Results.Redirect(QueryHelpers.AddQueryString(redirectUri, parameters));
    }

    private static IResult ExpiredPage() =>
        Results.Content(
            Pages.Message(
                "Request expired",
                "This sign-in request is no longer valid. Start the flow again from the client."),
            "text/html",
            statusCode: 400);
}
