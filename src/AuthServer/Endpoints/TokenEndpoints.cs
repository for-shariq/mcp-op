using System.Net.Http.Headers;
using System.Text;
using AuthServer.Services;
using Microsoft.Extensions.Options;

namespace AuthServer.Endpoints;

/// <summary>
/// Token issuance: the authorization_code and refresh_token grants, plus introspection and
/// revocation to make the flow observable while debugging.
/// </summary>
public static class TokenEndpoints
{
    public static void MapTokenEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/token", async (
            HttpContext http,
            ClientStore clients,
            AuthCodeStore codes,
            TestUserStore users,
            TokenService tokens,
            IOptions<AuthServerOptions> options,
            ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("Token");

            if (!http.Request.HasFormContentType)
            {
                return TokenError("invalid_request", "Expected application/x-www-form-urlencoded.");
            }

            var form = await http.Request.ReadFormAsync();

            // Accept the client secret from either the Authorization header or the body: Teams and
            // MCP Inspector differ on which they use, and both are valid per OAuth 2.1.
            var (headerClientId, headerSecret) = ReadBasicAuth(http.Request.Headers.Authorization);
            var clientId = headerClientId ?? form["client_id"].ToString();
            var clientSecret = headerSecret ?? form["client_secret"].ToString();

            var client = clients.Find(clientId);
            if (client is null)
            {
                logger.LogWarning("Token request for unknown client {ClientId}", clientId);
                return TokenError("invalid_client", "Unknown client.", 401);
            }

            if (client.IsConfidential && !ClientStore.SecretMatches(client, clientSecret))
            {
                logger.LogWarning("Bad client secret for {ClientId}", clientId);
                return TokenError("invalid_client", "Client authentication failed.", 401);
            }

            var grantType = form["grant_type"].ToString();

            return grantType switch
            {
                "authorization_code" => HandleAuthorizationCode(
                    form, client, codes, users, tokens, options.Value, logger),

                "refresh_token" => HandleRefreshToken(
                    form, client, codes, users, tokens, options.Value, logger),

                _ => TokenError("unsupported_grant_type",
                    "Supported grant types: authorization_code, refresh_token."),
            };
        });

        // RFC 7662-ish. Not required by Copilot, but it makes "is this token actually valid?"
        // answerable without decoding a JWT by hand.
        app.MapPost("/introspect", async (HttpContext http, AuthCodeStore codes) =>
        {
            var form = await http.Request.ReadFormAsync();
            var refreshToken = codes.GetRefreshToken(form["token"].ToString());

            return refreshToken is null
                ? Results.Json(new { active = false })
                : Results.Json(new
                {
                    active = true,
                    token_type = "refresh_token",
                    client_id = refreshToken.ClientId,
                    sub = refreshToken.Subject,
                    scope = string.Join(' ', refreshToken.Scopes),
                    aud = refreshToken.Resource,
                    exp = refreshToken.ExpiresAt.ToUnixTimeSeconds(),
                });
        });

        app.MapPost("/revoke", async (HttpContext http, AuthCodeStore codes) =>
        {
            var form = await http.Request.ReadFormAsync();
            codes.Revoke(form["token"].ToString());

            // RFC 7009 says return 200 even for an unknown token, so this reveals nothing.
            return Results.Ok();
        });

        // Forces re-authentication for a user, to test Copilot's sign-in recovery path.
        app.MapPost("/debug/revoke-user/{subject}", (string subject, AuthCodeStore codes) =>
            Results.Json(new { subject, revoked = codes.RevokeAllForSubject(subject) }));
    }

    private static IResult HandleAuthorizationCode(
        IFormCollection form,
        OAuthClient client,
        AuthCodeStore codes,
        TestUserStore users,
        TokenService tokens,
        AuthServerOptions options,
        ILogger logger)
    {
        // Redeeming removes the code, so a replay of the same code lands here with nothing to find.
        var code = codes.RedeemCode(form["code"].ToString());
        if (code is null)
        {
            logger.LogWarning("Invalid, expired, or already-redeemed code presented by {ClientId}", client.ClientId);
            return TokenError("invalid_grant", "The authorization code is invalid, expired, or already used.");
        }

        if (code.ClientId != client.ClientId)
        {
            logger.LogWarning("Code issued to {Issued} presented by {Presenter}", code.ClientId, client.ClientId);
            return TokenError("invalid_grant", "The authorization code was issued to a different client.");
        }

        // The redirect URI must match the one the code was bound to, per OAuth 2.1.
        var redirectUri = form["redirect_uri"].ToString();
        if (!string.IsNullOrEmpty(redirectUri) && redirectUri != code.RedirectUri)
        {
            return TokenError("invalid_grant", "redirect_uri does not match the authorization request.");
        }

        if (!AuthCodeStore.VerifyPkce(code.CodeChallenge, form["code_verifier"].ToString()))
        {
            logger.LogWarning("PKCE verification failed for client {ClientId}", client.ClientId);
            return TokenError("invalid_grant", "PKCE verification failed.");
        }

        var user = users.Find(code.Subject);
        if (user is null)
        {
            return TokenError("invalid_grant", "The user no longer exists.");
        }

        return IssueTokens(user, client, code.Scopes, code.Resource, codes, tokens, options, logger);
    }

    private static IResult HandleRefreshToken(
        IFormCollection form,
        OAuthClient client,
        AuthCodeStore codes,
        TestUserStore users,
        TokenService tokens,
        AuthServerOptions options,
        ILogger logger)
    {
        var presented = form["refresh_token"].ToString();
        var refreshToken = codes.GetRefreshToken(presented);

        if (refreshToken is null)
        {
            return TokenError("invalid_grant", "The refresh token is invalid, expired, or revoked.");
        }

        if (refreshToken.ClientId != client.ClientId)
        {
            return TokenError("invalid_grant", "The refresh token was issued to a different client.");
        }

        var user = users.Find(refreshToken.Subject);
        if (user is null)
        {
            return TokenError("invalid_grant", "The user no longer exists.");
        }

        // A refresh may narrow scope but never widen it.
        var requested = Scopes.Parse(form["scope"].ToString());
        var scopes = requested.Length == 0
            ? refreshToken.Scopes
            : requested.Intersect(refreshToken.Scopes, StringComparer.Ordinal).ToArray();

        // Rotate: the presented token dies so a stolen copy is single-use.
        codes.Revoke(presented);

        return IssueTokens(user, client, scopes, refreshToken.Resource, codes, tokens, options, logger);
    }

    private static IResult IssueTokens(
        TestUser user,
        OAuthClient client,
        string[] scopes,
        string resource,
        AuthCodeStore codes,
        TokenService tokens,
        AuthServerOptions options,
        ILogger logger)
    {
        var (accessToken, expiresIn) = tokens.CreateAccessToken(user, client.ClientId, scopes, resource);

        var response = new Dictionary<string, object?>
        {
            ["access_token"] = accessToken,
            ["token_type"] = "Bearer",
            ["expires_in"] = expiresIn,
            ["scope"] = string.Join(' ', scopes),
        };

        // Only hand out a refresh token when offline_access was actually granted.
        if (scopes.Contains(Scopes.OfflineAccess, StringComparer.Ordinal))
        {
            var refreshToken = codes.IssueRefreshToken(
                client.ClientId, user.Subject, scopes, resource, options.RefreshTokenLifetimeDays);

            response["refresh_token"] = refreshToken.Token;
        }

        logger.LogInformation(
            "Issued access token for {Subject} to {ClientId}, aud={Resource}, scopes=[{Scopes}]",
            user.Subject, client.ClientId, resource, string.Join(' ', scopes));

        return Results.Json(response);
    }

    private static (string? ClientId, string? Secret) ReadBasicAuth(string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(authorizationHeader))
        {
            return (null, null);
        }

        if (!AuthenticationHeaderValue.TryParse(authorizationHeader, out var parsed) ||
            !string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(parsed.Parameter))
        {
            return (null, null);
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
            var separator = decoded.IndexOf(':');

            return separator < 0
                ? (null, null)
                : (Uri.UnescapeDataString(decoded[..separator]),
                   Uri.UnescapeDataString(decoded[(separator + 1)..]));
        }
        catch (FormatException)
        {
            return (null, null);
        }
    }

    private static IResult TokenError(string error, string description, int statusCode = 400) =>
        Results.Json(new { error, error_description = description }, statusCode: statusCode);
}
