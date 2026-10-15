using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace AuthServer.Services;

/// <summary>
/// In-memory client registry. Seeded with one static client for the Teams developer portal path,
/// and extended at runtime by RFC 7591 dynamic client registration.
/// </summary>
public sealed class ClientStore
{
    /// <summary>
    /// The only redirect URI Microsoft 365 Copilot ever uses. It is fixed by the platform and
    /// cannot be customised per app, so the seeded client is registered with exactly this value.
    /// </summary>
    public const string TeamsRedirectUri = "https://teams.microsoft.com/api/platform/v1.0/oAuthRedirect";

    private readonly ConcurrentDictionary<string, OAuthClient> _clients = new(StringComparer.Ordinal);
    private readonly ILogger<ClientStore> _logger;

    public ClientStore(IOptions<AuthServerOptions> options, ILogger<ClientStore> logger)
    {
        _logger = logger;
        var seed = options.Value.SeedClient;

        var client = new OAuthClient
        {
            ClientId = seed.ClientId,
            ClientSecret = seed.ClientSecret,
            ClientName = seed.ClientName,
            // Localhost entries let MCP Inspector and curl drive the same client during local testing.
            RedirectUris =
            [
                TeamsRedirectUri,
                "http://localhost:6274/oauth/callback",
                "http://127.0.0.1:6274/oauth/callback",
                "http://localhost:8090/callback",
            ],
        };

        _clients[client.ClientId] = client;
        _logger.LogInformation("Seeded static client {ClientId}", client.ClientId);
    }

    public OAuthClient? Find(string? clientId) =>
        string.IsNullOrEmpty(clientId) ? null : _clients.GetValueOrDefault(clientId);

    public IReadOnlyCollection<OAuthClient> All => _clients.Values.ToArray();

    /// <summary>
    /// Registers a client per RFC 7591. A secret is always issued: Copilot does not support
    /// dynamic client registration without one.
    /// </summary>
    public OAuthClient Register(string clientName, IReadOnlyList<string> redirectUris)
    {
        var client = new OAuthClient
        {
            ClientId = $"dcr-{Guid.NewGuid():N}",
            ClientSecret = RandomToken(32),
            ClientName = clientName,
            RedirectUris = redirectUris,
            IsDynamicallyRegistered = true,
        };

        _clients[client.ClientId] = client;
        _logger.LogInformation(
            "DCR registered client {ClientId} ({ClientName}) with redirect URIs {RedirectUris}",
            client.ClientId, client.ClientName, string.Join(", ", redirectUris));

        return client;
    }

    /// <summary>Constant-time secret comparison, so this doesn't model a timing leak.</summary>
    public static bool SecretMatches(OAuthClient client, string? presented)
    {
        if (client.ClientSecret is null) return presented is null or "";
        if (string.IsNullOrEmpty(presented)) return false;

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(client.ClientSecret),
            System.Text.Encoding.UTF8.GetBytes(presented));
    }

    public static string RandomToken(int bytes) =>
        Base64UrlEncode(RandomNumberGenerator.GetBytes(bytes));

    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
