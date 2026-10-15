namespace AuthServer.Services;

/// <summary>The scopes this test rig understands.</summary>
public static class Scopes
{
    public const string ToolsRead = "mcp:tools.read";
    public const string ToolsWrite = "mcp:tools.write";

    /// <summary>
    /// Requests a refresh token. Deliberately NOT advertised by the resource server, since per the
    /// MCP spec it is a client concern rather than a resource requirement.
    /// </summary>
    public const string OfflineAccess = "offline_access";

    /// <summary>Everything the AS will issue, advertised in RFC 8414 metadata.</summary>
    public static readonly string[] Supported = [ToolsRead, ToolsWrite, OfflineAccess];

    /// <summary>Granted when a client asks for nothing in particular.</summary>
    public static readonly string[] Default = [ToolsRead];

    public static string[] Parse(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? []
            : raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Distinct(StringComparer.Ordinal)
                 .ToArray();

    /// <summary>Drops anything we don't recognise rather than failing the whole request.</summary>
    public static string[] Filter(string[] requested) =>
        requested.Where(s => Supported.Contains(s, StringComparer.Ordinal)).ToArray();

    public static string Describe(string scope) => scope switch
    {
        ToolsRead => "Read your tasks and profile",
        ToolsWrite => "Create and modify your tasks",
        OfflineAccess => "Stay signed in (issue a refresh token)",
        _ => scope,
    };
}
