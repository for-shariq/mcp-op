using System.ComponentModel;
using System.Security.Claims;
using McpServer.Auth;
using McpServer.Data;
using ModelContextProtocol.Server;

namespace McpServer.Tools;

/// <summary>
/// Test tools for exercising the Copilot OAuth path. Each one is here to prove a specific property
/// of the auth flow rather than to be independently useful.
/// </summary>
[McpServerToolType]
public sealed class TestTools(
    IHttpContextAccessor httpContextAccessor,
    TaskStore tasks,
    ILogger<TestTools> logger)
{
    private ClaimsPrincipal User =>
        httpContextAccessor.HttpContext?.User
        ?? throw new InvalidOperationException("No HTTP context: this server only runs over HTTP transport.");

    /// <summary>
    /// The token subject, which keys all per-user data. Fails loudly rather than with a null
    /// reference, because a missing sub almost always means claim mapping is rewriting it.
    /// </summary>
    private string Subject =>
        User.FindFirstValue("sub")
        ?? throw new InvalidOperationException(
            "The access token carries no 'sub' claim, so the caller cannot be identified.");

    /// <summary>Proves the validated token's identity reaches tool code. The primary smoke test.</summary>
    [McpServerTool(Name = "whoami", Title = "Who am I?", ReadOnly = true)]
    [Description("Returns the identity of the signed-in user, taken from the validated OAuth access token. Use this to confirm who the user is.")]
    public object WhoAmI()
    {
        var subject = Subject;
        logger.LogInformation("whoami called by {Subject}", subject);

        return new
        {
            subject,
            name = User.FindFirstValue("name"),
            userName = User.FindFirstValue("preferred_username"),
            department = User.FindFirstValue("department"),
            grantedScopes = User.GetScopes(),
        };
    }

    /// <summary>Proves audience and issuer binding is actually working.</summary>
    [McpServerTool(Name = "get_token_info", Title = "Inspect access token", ReadOnly = true)]
    [Description("Returns the issuer, audience, expiry and ID of the access token used for this call. A debugging aid for verifying OAuth configuration.")]
    public object GetTokenInfo()
    {
        var expiry = User.FindFirstValue("exp");

        return new
        {
            issuer = User.FindFirstValue("iss"),
            audience = User.FindFirstValue("aud"),
            clientId = User.FindFirstValue("client_id"),
            tokenId = User.FindFirstValue("jti"),
            scopes = User.GetScopes(),
            expiresAt = long.TryParse(expiry, out var unix)
                ? DateTimeOffset.FromUnixTimeSeconds(unix).ToString("u")
                : null,
        };
    }

    /// <summary>
    /// Proves per-user data isolation. Two test users must see different lists; if they don't, the
    /// token subject isn't reaching the store.
    /// </summary>
    [McpServerTool(Name = "list_my_tasks", Title = "List my tasks", ReadOnly = true)]
    [Description("Lists the tasks belonging to the signed-in user. Each user sees only their own tasks.")]
    public object ListMyTasks()
    {
        var subject = Subject;
        var items = tasks.List(subject);

        logger.LogInformation("list_my_tasks returned {Count} tasks for {Subject}", items.Count, subject);

        return new
        {
            owner = User.FindFirstValue("preferred_username"),
            count = items.Count,
            tasks = items.Select(t => new { t.Id, t.Title, t.Status, createdAt = t.CreatedAt.ToString("u") }),
        };
    }

    /// <summary>
    /// Proves scope enforcement and Copilot's confirmation card. Requests without
    /// <c>mcp:tools.write</c> never reach this method: <see cref="ScopeEnforcementMiddleware"/>
    /// rejects them at the HTTP layer with a 403 and an insufficient_scope challenge.
    /// </summary>
    [McpServerTool(Name = "create_task", Title = "Create a task", Destructive = false, Idempotent = false)]
    [Description("Creates a new task for the signed-in user. Requires the mcp:tools.write scope.")]
    public object CreateTask(
        [Description("Short title describing the task to create.")] string title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            throw new ArgumentException("A task title is required.", nameof(title));
        }

        var subject = Subject;

        // Defence in depth: the middleware already enforces this, but a tool that mutates state
        // shouldn't depend solely on an upstream check.
        if (!User.HasScope(McpScopes.ToolsWrite))
        {
            throw new InvalidOperationException($"The {McpScopes.ToolsWrite} scope is required to create tasks.");
        }

        var task = tasks.Create(subject, title.Trim());
        logger.LogInformation("create_task created task {TaskId} for {Subject}", task.Id, subject);

        return new { created = true, task.Id, task.Title, task.Status };
    }

    /// <summary>
    /// Proves the client's re-authentication path. The tool body is never reached: the middleware
    /// intercepts it and returns a 401 carrying the resource_metadata challenge, so you can watch
    /// how Copilot or Inspector recovers.
    /// </summary>
    [McpServerTool(Name = "force_unauthorized", Title = "Force a 401", ReadOnly = true)]
    [Description("Diagnostic tool that always fails with an authentication error, to test the client's sign-in recovery behaviour.")]
    public object ForceUnauthorized() =>
        throw new InvalidOperationException("Unreachable: intercepted by ScopeEnforcementMiddleware.");
}
