using McpServer.Auth;
using McpServer.Data;
using McpServer.Tools;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Both URLs come from configuration because they change every time the dev tunnel changes, and
// issuer, audience and resource metadata all have to move together.
var publicUrl = builder.Configuration["Mcp:PublicUrl"] ?? "http://localhost:7071";
var authServerUrl = builder.Configuration["Mcp:AuthServerUrl"] ?? "http://localhost:7029";
// The canonical resource URI is the MCP endpoint, not the bare host: the MCP spec asks for the
// most specific URI, and this is also the value that goes in the Teams OAuth registration's
// Base URL and the plugin manifest's MCP server spec.
var resourceUri = $"{publicUrl.TrimEnd('/')}/mcp";
var urls = new McpServerUrls(publicUrl, authServerUrl);

builder.Services.AddSingleton(urls);

builder.Services.AddAuthentication(options =>
{
    // The MCP scheme handles the challenge, so a 401 carries the RFC 9728 resource_metadata
    // pointer; JWT bearer does the actual token validation.
    options.DefaultChallengeScheme = McpAuthenticationDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.Authority = authServerUrl;

    // Without this, the handler rewrites short JWT claim names to long WS-* URIs, so "sub"
    // arrives as ClaimTypes.NameIdentifier and every FindFirstValue("sub") in a tool returns null.
    options.MapInboundClaims = false;
    options.MetadataAddress = $"{authServerUrl.TrimEnd('/')}/.well-known/openid-configuration";

    // The tunnel terminates TLS, so the app itself speaks plain HTTP in development.
    options.RequireHttpsMetadata = builder.Environment.IsProduction();

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = authServerUrl.TrimEnd('/'),

        // The security boundary. Refusing tokens that weren't minted for this resource is what
        // stops a token issued for some other service being replayed here; the MCP spec makes
        // this a MUST, not a nicety.
        ValidAudience = resourceUri,

        NameClaimType = "name",
        RoleClaimType = "roles",
        ClockSkew = TimeSpan.FromSeconds(30),
    };

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearer");

            logger.LogInformation(
                "Token accepted for {User} ({Subject})",
                context.Principal?.Identity?.Name ?? "unknown",
                context.Principal?.FindFirst("sub")?.Value ?? "unknown");

            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>().CreateLogger("JwtBearer");

            logger.LogWarning("Token rejected: {Reason}", context.Exception.Message);
            return Task.CompletedTask;
        },
    };
})
// Publishes /.well-known/oauth-protected-resource (RFC 9728) and adds resource_metadata to the
// 401 challenge, so an MCP client can discover the authorization server unaided.
.AddMcp(options =>
{
    options.ResourceMetadata = new ProtectedResourceMetadata
    {
        Resource = resourceUri,
        ResourceName = "mcp-op test MCP server",
        AuthorizationServers = { authServerUrl },
        ScopesSupported = [McpScopes.ToolsRead, McpScopes.ToolsWrite],
    };
});

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<TaskStore>();

builder.Services.AddMcpServer()
    .WithTools<TestTools>()
    .WithHttpTransport();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Must sit after authentication so context.User is populated, and before MapMcp so it can
// short-circuit a tools/call with a 401 or 403 challenge.
app.UseMiddleware<ScopeEnforcementMiddleware>();

app.MapMcp("/mcp").RequireAuthorization();

// Unauthenticated health check, handy for confirming the tunnel is up independently of OAuth.
app.MapGet("/health", () => Results.Json(new
{
    status = "ok",
    resource = resourceUri,
    authorizationServer = authServerUrl,
    resourceMetadata = urls.ResourceMetadata,
})).AllowAnonymous();

app.Logger.LogInformation("Resource (audience): {Resource}", resourceUri);
app.Logger.LogInformation("Authorization server: {AuthServer}", authServerUrl);

app.Run();
