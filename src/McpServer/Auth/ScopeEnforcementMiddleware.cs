using System.Security.Claims;
using System.Text.Json;

namespace McpServer.Auth;

public static class McpScopes
{
    public const string ToolsRead = "mcp:tools.read";
    public const string ToolsWrite = "mcp:tools.write";
}

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Reads the space-delimited <c>scope</c> claim. Some issuers emit <c>scp</c> instead, so both
    /// are accepted.
    /// </summary>
    public static string[] GetScopes(this ClaimsPrincipal user)
    {
        var raw = user.FindFirstValue("scope") ?? user.FindFirstValue("scp");

        return string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public static bool HasScope(this ClaimsPrincipal user, string scope) =>
        user.GetScopes().Contains(scope, StringComparer.Ordinal);
}

/// <summary>
/// Enforces per-tool scope requirements at the HTTP layer.
/// <para>
/// This has to be middleware rather than a check inside the tool. The MCP spec requires an
/// insufficient-scope failure to surface as an HTTP 403 with a <c>WWW-Authenticate</c> challenge,
/// which is what drives a client's step-up authorization flow. By the time a tool method runs the
/// JSON-RPC response is already being composed, so an exception there becomes a tool error with a
/// 200 status and no challenge — the client has nothing to step up from.
/// </para>
/// </summary>
public sealed class ScopeEnforcementMiddleware(RequestDelegate next, ILogger<ScopeEnforcementMiddleware> logger)
{
    /// <summary>Tools that need more than the baseline read scope.</summary>
    private static readonly Dictionary<string, string> RequiredScopes = new(StringComparer.Ordinal)
    {
        ["list_my_tasks"] = McpScopes.ToolsRead,
        ["create_task"] = McpScopes.ToolsWrite,
    };

    /// <summary>Always fails with a 401, to exercise the client's re-authentication path.</summary>
    private const string AlwaysUnauthorizedTool = "force_unauthorized";

    public async Task InvokeAsync(HttpContext context, McpServerUrls urls)
    {
        var toolName = await ReadToolCallNameAsync(context);

        if (toolName is null)
        {
            // Not a tools/call request (initialize, tools/list, notifications, GET for the SSE
            // stream). Those must pass through untouched or discovery breaks.
            await next(context);
            return;
        }

        if (toolName == AlwaysUnauthorizedTool)
        {
            logger.LogInformation("force_unauthorized invoked: returning a 401 challenge");

            await ChallengeAsync(context, urls, StatusCodes.Status401Unauthorized,
                error: "invalid_token",
                description: "This diagnostic tool always rejects the token so you can observe re-authentication.",
                scope: null);

            return;
        }

        if (RequiredScopes.TryGetValue(toolName, out var required) &&
            !context.User.HasScope(required))
        {
            logger.LogWarning(
                "Tool {Tool} requires {RequiredScope}; token carries [{GrantedScopes}]",
                toolName, required, string.Join(' ', context.User.GetScopes()));

            // 403 + insufficient_scope is what tells the client to request a wider scope and retry,
            // per RFC 6750 section 3.1.
            await ChallengeAsync(context, urls, StatusCodes.Status403Forbidden,
                error: "insufficient_scope",
                description: $"The {required} scope is required to call {toolName}.",
                scope: required);

            return;
        }

        await next(context);
    }

    /// <summary>
    /// Returns the tool name when the request is a JSON-RPC <c>tools/call</c>, otherwise null.
    /// Buffers the body and rewinds it so the MCP handler can read it again.
    /// </summary>
    private static async Task<string?> ReadToolCallNameAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            return null;
        }

        var contentType = context.Request.ContentType;
        if (contentType is null || !contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        context.Request.EnableBuffering();

        try
        {
            using var document = await JsonDocument.ParseAsync(
                context.Request.Body, cancellationToken: context.RequestAborted);

            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("method", out var method) ||
                method.GetString() != "tools/call" ||
                !document.RootElement.TryGetProperty("params", out var parameters) ||
                !parameters.TryGetProperty("name", out var name))
            {
                return null;
            }

            return name.GetString();
        }
        catch (JsonException)
        {
            // Malformed JSON is the MCP handler's problem to report, not ours.
            return null;
        }
        finally
        {
            context.Request.Body.Position = 0;
        }
    }

    private static async Task ChallengeAsync(
        HttpContext context, McpServerUrls urls, int statusCode, string error, string description, string? scope)
    {
        var parts = new List<string> { $"error=\"{error}\"" };

        if (scope is not null)
        {
            parts.Add($"scope=\"{scope}\"");
        }

        // Included on 403s as well as 401s, so a client that only learns about the resource from
        // the challenge can still find the authorization server.
        parts.Add($"resource_metadata=\"{urls.ResourceMetadata}\"");
        parts.Add($"error_description=\"{description}\"");

        context.Response.StatusCode = statusCode;
        context.Response.Headers.WWWAuthenticate = $"Bearer {string.Join(", ", parts)}";

        await context.Response.WriteAsJsonAsync(new
        {
            error,
            error_description = description,
        });
    }
}

/// <summary>The server's own public URLs, resolved once from configuration at startup.</summary>
public sealed record McpServerUrls(string PublicUrl, string AuthServerUrl)
{
    /// <summary>
    /// RFC 9728 inserts the resource path into the well-known path, so a resource identified by
    /// <c>/mcp</c> publishes its metadata at <c>/.well-known/oauth-protected-resource/mcp</c>.
    /// This has to match what the SDK's challenge emits or clients follow a dead link.
    /// </summary>
    public string ResourceMetadata => $"{PublicUrl.TrimEnd('/')}/.well-known/oauth-protected-resource/mcp";
}
