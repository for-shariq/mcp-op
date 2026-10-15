using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Services;

/// <summary>
/// Mints RS256 access tokens and publishes the matching JWKS. The signing key is generated on
/// first run and persisted so that restarting the AS doesn't invalidate tokens the MCP server
/// has already cached keys for.
/// </summary>
public sealed class TokenService
{
    private readonly AuthServerOptions _options;
    private readonly RsaSecurityKey _signingKey;
    private readonly JsonWebTokenHandler _handler = new();
    private readonly ILogger<TokenService> _logger;

    public TokenService(IOptions<AuthServerOptions> options, IHostEnvironment env, ILogger<TokenService> logger)
    {
        _options = options.Value;
        _logger = logger;

        var rsa = LoadOrCreateKey(Path.Combine(env.ContentRootPath, ".keys", "signing-key.pkcs8"));
        _signingKey = new RsaSecurityKey(rsa) { KeyId = ComputeKeyId(rsa) };

        _logger.LogInformation("Signing key ready, kid={Kid}", _signingKey.KeyId);
    }

    public string KeyId => _signingKey.KeyId;

    /// <summary>
    /// Resolves the token audience. When a client supplies an RFC 8707 <c>resource</c> we honour
    /// it; when it doesn't — which is what Teams does on the static registration path — we fall
    /// back to the configured MCP server URI. Without this fallback the MCP server's audience
    /// check rejects every token Copilot presents.
    /// </summary>
    public string ResolveResource(string? requestedResource)
    {
        if (string.IsNullOrWhiteSpace(requestedResource))
            return _options.DefaultResource;

        var normalised = requestedResource.TrimEnd('/');
        var allowed = _options.AllowedResources.Length > 0
            ? _options.AllowedResources
            : [_options.DefaultResource];

        var match = allowed.FirstOrDefault(r =>
            string.Equals(r.TrimEnd('/'), normalised, StringComparison.OrdinalIgnoreCase));

        if (match is null)
        {
            _logger.LogWarning(
                "Rejecting unknown resource {Resource}; allowed: {Allowed}",
                requestedResource, string.Join(", ", allowed));
            throw new InvalidResourceException(requestedResource);
        }

        return match;
    }

    public (string Token, int ExpiresInSeconds) CreateAccessToken(
        TestUser user, string clientId, string[] scopes, string resource)
    {
        var lifetime = TimeSpan.FromMinutes(_options.AccessTokenLifetimeMinutes);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.PublicUrl,
            Audience = resource,
            Expires = DateTime.UtcNow.Add(lifetime),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = user.Subject,
                ["name"] = user.Name,
                ["preferred_username"] = user.UserName,
                ["department"] = user.Department,
                ["scope"] = string.Join(' ', scopes),
                ["client_id"] = clientId,
                ["jti"] = Guid.NewGuid().ToString("N"),
            },
        };

        return (_handler.CreateToken(descriptor), (int)lifetime.TotalSeconds);
    }

    /// <summary>The public half of the signing key, as an RFC 7517 JWK set.</summary>
    public object BuildJwks()
    {
        var parameters = _signingKey.Rsa!.ExportParameters(includePrivateParameters: false);

        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = _signingKey.KeyId,
                    n = ClientStore.Base64UrlEncode(parameters.Modulus!),
                    e = ClientStore.Base64UrlEncode(parameters.Exponent!),
                },
            },
        };
    }

    private static RSA LoadOrCreateKey(string path)
    {
        var rsa = RSA.Create(2048);

        if (File.Exists(path))
        {
            rsa.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _);
            return rsa;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, rsa.ExportPkcs8PrivateKey());
        return rsa;
    }

    private static string ComputeKeyId(RSA rsa)
    {
        var modulus = rsa.ExportParameters(false).Modulus!;
        return ClientStore.Base64UrlEncode(SHA256.HashData(modulus))[..16];
    }
}

/// <summary>Thrown when a client asks for a token aimed at a resource this AS doesn't serve.</summary>
public sealed class InvalidResourceException(string resource)
    : Exception($"Unknown resource '{resource}'.")
{
    public string Resource { get; } = resource;
}
