using System.Text.Json;
using System.Text.Json.Serialization;
using AuthServer.Services;

namespace AuthServer.Endpoints;

/// <summary>
/// RFC 7591 dynamic client registration. This is the endpoint Microsoft Entra ID does not have,
/// and therefore the reason this test rig runs its own authorization server.
/// </summary>
public static class RegistrationEndpoints
{
    public static void MapRegistrationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/register", (ClientRegistrationRequest request, ClientStore clients) =>
        {
            if (request.RedirectUris is not { Count: > 0 })
            {
                return Results.BadRequest(new
                {
                    error = "invalid_redirect_uri",
                    error_description = "redirect_uris is required and must contain at least one entry.",
                });
            }

            foreach (var uri in request.RedirectUris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed) || parsed.Fragment.Length > 0)
                {
                    return Results.BadRequest(new
                    {
                        error = "invalid_redirect_uri",
                        error_description = $"'{uri}' is not an absolute URI without a fragment.",
                    });
                }
            }

            // Reject grant types we don't implement rather than silently registering a client that
            // will fail at /token.
            var unsupported = (request.GrantTypes ?? [])
                .Where(g => g is not ("authorization_code" or "refresh_token"))
                .ToArray();

            if (unsupported.Length > 0)
            {
                return Results.BadRequest(new
                {
                    error = "invalid_client_metadata",
                    error_description = $"Unsupported grant_types: {string.Join(", ", unsupported)}.",
                });
            }

            var client = clients.Register(
                request.ClientName ?? "Dynamically registered client",
                request.RedirectUris);

            // 201 with client_secret. Copilot does not support DCR without a secret, so this is
            // always a confidential client.
            return Results.Created($"/register/{client.ClientId}", new Dictionary<string, object?>
            {
                ["client_id"] = client.ClientId,
                ["client_secret"] = client.ClientSecret,
                ["client_id_issued_at"] = client.IssuedAt.ToUnixTimeSeconds(),
                ["client_secret_expires_at"] = 0, // 0 = never expires, per RFC 7591
                ["client_name"] = client.ClientName,
                ["redirect_uris"] = client.RedirectUris,
                ["grant_types"] = client.GrantTypes,
                ["response_types"] = new[] { "code" },
                ["token_endpoint_auth_method"] = "client_secret_post",
                ["scope"] = string.Join(' ', Scopes.Supported),
            });
        });

        // Handy during debugging: shows what has registered itself so far.
        app.MapGet("/debug/clients", (ClientStore clients) => Results.Json(
            clients.All.Select(c => new
            {
                c.ClientId,
                c.ClientName,
                c.RedirectUris,
                c.IsDynamicallyRegistered,
                HasSecret = c.IsConfidential,
                c.IssuedAt,
            })));
    }
}

/// <summary>The subset of RFC 7591 client metadata this AS honours.</summary>
public sealed class ClientRegistrationRequest
{
    [JsonPropertyName("client_name")]
    public string? ClientName { get; set; }

    [JsonPropertyName("redirect_uris")]
    public List<string>? RedirectUris { get; set; }

    [JsonPropertyName("grant_types")]
    public List<string>? GrantTypes { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; set; }
}
