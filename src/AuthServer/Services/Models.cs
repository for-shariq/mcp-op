namespace AuthServer.Services;

/// <summary>Configuration for the test authorization server.</summary>
public sealed class AuthServerOptions
{
    /// <summary>Public base URL of this authorization server. Becomes the token <c>iss</c>.</summary>
    public string PublicUrl { get; set; } = "http://localhost:7029";

    /// <summary>
    /// Canonical URI of the MCP server. Used as the token <c>aud</c> when the client does not send
    /// an RFC 8707 <c>resource</c> parameter, which is what happens on Copilot's static
    /// registration path.
    /// </summary>
    public string DefaultResource { get; set; } = "http://localhost:7071";

    /// <summary>Resource URIs this AS is willing to mint tokens for.</summary>
    public string[] AllowedResources { get; set; } = [];

    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int RefreshTokenLifetimeDays { get; set; } = 30;

    /// <summary>Statically registered client, for the Teams developer portal / Agents Toolkit path.</summary>
    public SeedClientOptions SeedClient { get; set; } = new();
}

public sealed class SeedClientOptions
{
    public string ClientId { get; set; } = "copilot-test-client";
    public string ClientSecret { get; set; } = "copilot-test-secret";
    public string ClientName { get; set; } = "Microsoft 365 Copilot (static registration)";
}

/// <summary>A registered OAuth client, whether seeded statically or created via RFC 7591 DCR.</summary>
public sealed record OAuthClient
{
    public required string ClientId { get; init; }
    /// <summary>Null for a public client; DCR always issues one because Copilot requires it.</summary>
    public string? ClientSecret { get; init; }
    public required string ClientName { get; init; }
    public required IReadOnlyList<string> RedirectUris { get; init; }
    public IReadOnlyList<string> GrantTypes { get; init; } = ["authorization_code", "refresh_token"];
    public DateTimeOffset IssuedAt { get; init; } = DateTimeOffset.UtcNow;
    public bool IsDynamicallyRegistered { get; init; }

    public bool IsConfidential => !string.IsNullOrEmpty(ClientSecret);
}

/// <summary>A test user. No passwords: this is a test rig, you pick an identity from a list.</summary>
public sealed record TestUser(string Subject, string Name, string UserName, string Department);

/// <summary>An /authorize request parked while the user signs in and consents.</summary>
public sealed record PendingAuthRequest
{
    public required string RequestId { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string[] Scopes { get; init; }
    public string? State { get; init; }
    public required string CodeChallenge { get; init; }
    /// <summary>Resolved audience: the RFC 8707 resource parameter, or the configured default.</summary>
    public required string Resource { get; init; }
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddMinutes(10);
}

/// <summary>An issued authorization code. Single use, short lived, PKCE-bound.</summary>
public sealed record AuthorizationCode
{
    public required string Code { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string Subject { get; init; }
    public required string[] Scopes { get; init; }
    public required string CodeChallenge { get; init; }
    public required string Resource { get; init; }
    public DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddSeconds(60);
}

/// <summary>An opaque refresh token, issued only when <c>offline_access</c> was granted.</summary>
public sealed record RefreshToken
{
    public required string Token { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string[] Scopes { get; init; }
    public required string Resource { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public bool Revoked { get; set; }
}
