namespace AuthServer.Services;

/// <summary>
/// Three fixed test identities. There are no passwords by design: the login page is a picker, so
/// you can switch users instantly and watch per-user isolation in the MCP tools.
/// </summary>
public sealed class TestUserStore
{
    private static readonly TestUser[] Users =
    [
        new("user-ada",   "Ada Lovelace",   "ada@contoso.test",   "Engineering"),
        new("user-grace", "Grace Hopper",   "grace@contoso.test", "Engineering"),
        new("user-alan",  "Alan Turing",    "alan@contoso.test",  "Research"),
    ];

    public IReadOnlyList<TestUser> All => Users;

    public TestUser? Find(string subject) =>
        Users.FirstOrDefault(u => u.Subject == subject);
}
