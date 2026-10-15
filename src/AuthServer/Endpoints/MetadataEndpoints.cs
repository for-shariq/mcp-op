using AuthServer.Services;
using Microsoft.Extensions.Options;

namespace AuthServer.Endpoints;

public static class MetadataEndpoints
{
    public static void MapMetadataEndpoints(this IEndpointRouteBuilder app)
    {
        // RFC 8414. Agents Toolkit reads this to discover the authorize/token/refresh endpoints,
        // and the Copilot DCR path reads registration_endpoint from it.
        app.MapGet("/.well-known/oauth-authorization-server", BuildMetadata);

        // Some MCP clients try OpenID Connect discovery first. Serving the same document from both
        // paths means discovery succeeds whichever order a client tries.
        app.MapGet("/.well-known/openid-configuration", BuildMetadata);

        app.MapGet("/.well-known/jwks.json", (TokenService tokens) => Results.Json(tokens.BuildJwks()));

        app.MapGet("/", (IOptions<AuthServerOptions> options) => Results.Json(new
        {
            service = "mcp-op test authorization server",
            issuer = options.Value.PublicUrl,
            defaultResource = options.Value.DefaultResource,
            metadata = $"{options.Value.PublicUrl}/.well-known/oauth-authorization-server",
        }));
    }

    private static IResult BuildMetadata(IOptions<AuthServerOptions> options)
    {
        var issuer = options.Value.PublicUrl.TrimEnd('/');

        return Results.Json(new Dictionary<string, object>
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = $"{issuer}/authorize",
            ["token_endpoint"] = $"{issuer}/token",
            ["registration_endpoint"] = $"{issuer}/register",
            ["introspection_endpoint"] = $"{issuer}/introspect",
            ["revocation_endpoint"] = $"{issuer}/revoke",
            ["jwks_uri"] = $"{issuer}/.well-known/jwks.json",
            ["scopes_supported"] = Scopes.Supported,
            ["response_types_supported"] = new[] { "code" },
            ["response_modes_supported"] = new[] { "query" },
            ["grant_types_supported"] = new[] { "authorization_code", "refresh_token" },
            // S256 only. Copilot enables PKCE by default and plain offers no protection.
            ["code_challenge_methods_supported"] = new[] { "S256" },
            ["token_endpoint_auth_methods_supported"] = new[]
            {
                "client_secret_post", "client_secret_basic", "none",
            },
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
            // RFC 9207. The MCP spec expects the iss parameter on authorization responses, and
            // Inspector rejects responses that omit it once this is advertised.
            ["authorization_response_iss_parameter_supported"] = true,
            ["service_documentation"] = "https://modelcontextprotocol.io/specification/draft/basic/authorization",
        });
    }
}
