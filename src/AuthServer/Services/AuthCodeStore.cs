using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Services;

/// <summary>
/// Holds parked /authorize requests, single-use authorization codes, and refresh tokens.
/// All in memory: restarting the AS invalidates live grants, which is fine for a test rig.
/// </summary>
public sealed class AuthCodeStore
{
    private readonly ConcurrentDictionary<string, PendingAuthRequest> _pending = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AuthorizationCode> _codes = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, RefreshToken> _refreshTokens = new(StringComparer.Ordinal);

    // --- pending /authorize requests -------------------------------------------------

    public PendingAuthRequest Park(PendingAuthRequest request)
    {
        Sweep();
        _pending[request.RequestId] = request;
        return request;
    }

    public PendingAuthRequest? GetPending(string? requestId) =>
        string.IsNullOrEmpty(requestId) ? null
        : _pending.TryGetValue(requestId, out var r) && r.ExpiresAt > DateTimeOffset.UtcNow ? r
        : null;

    public void RemovePending(string requestId) => _pending.TryRemove(requestId, out _);

    // --- authorization codes ---------------------------------------------------------

    public AuthorizationCode IssueCode(PendingAuthRequest request, string subject)
    {
        var code = new AuthorizationCode
        {
            Code = ClientStore.RandomToken(32),
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Subject = subject,
            Scopes = request.Scopes,
            CodeChallenge = request.CodeChallenge,
            Resource = request.Resource,
        };

        _codes[code.Code] = code;
        return code;
    }

    /// <summary>
    /// Atomically removes and returns a code. Removal is the point: replaying a code must fail,
    /// so redemption is a one-shot take rather than a lookup.
    /// </summary>
    public AuthorizationCode? RedeemCode(string? code)
    {
        if (string.IsNullOrEmpty(code)) return null;
        if (!_codes.TryRemove(code, out var found)) return null;
        return found.ExpiresAt > DateTimeOffset.UtcNow ? found : null;
    }

    // --- refresh tokens ---------------------------------------------------------------

    public RefreshToken IssueRefreshToken(string clientId, string subject, string[] scopes, string resource, int lifetimeDays)
    {
        var token = new RefreshToken
        {
            Token = ClientStore.RandomToken(32),
            ClientId = clientId,
            Subject = subject,
            Scopes = scopes,
            Resource = resource,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(lifetimeDays),
        };

        _refreshTokens[token.Token] = token;
        return token;
    }

    public RefreshToken? GetRefreshToken(string? token) =>
        string.IsNullOrEmpty(token) ? null
        : _refreshTokens.TryGetValue(token, out var rt) && !rt.Revoked && rt.ExpiresAt > DateTimeOffset.UtcNow ? rt
        : null;

    /// <summary>Rotates on use: the presented token is revoked and a fresh one issued.</summary>
    public void Revoke(string token)
    {
        if (_refreshTokens.TryGetValue(token, out var rt)) rt.Revoked = true;
    }

    public int RevokeAllForSubject(string subject)
    {
        var affected = _refreshTokens.Values.Where(t => t.Subject == subject && !t.Revoked).ToArray();
        foreach (var t in affected) t.Revoked = true;
        return affected.Length;
    }

    // --- PKCE -------------------------------------------------------------------------

    /// <summary>
    /// Verifies an RFC 7636 S256 challenge. Only S256 is supported; <c>plain</c> is rejected at
    /// /authorize, so there is no downgrade path here.
    /// </summary>
    public static bool VerifyPkce(string codeChallenge, string? codeVerifier)
    {
        if (string.IsNullOrEmpty(codeVerifier)) return false;

        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        var computed = ClientStore.Base64UrlEncode(hash);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(computed),
            Encoding.ASCII.GetBytes(codeChallenge));
    }

    private void Sweep()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (key, value) in _pending)
            if (value.ExpiresAt <= now) _pending.TryRemove(key, out _);
        foreach (var (key, value) in _codes)
            if (value.ExpiresAt <= now) _codes.TryRemove(key, out _);
    }
}
