using AuthServer.Endpoints;
using AuthServer.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthServerOptions>(builder.Configuration.GetSection("OAuth"));
builder.Services.AddSingleton<ClientStore>();
builder.Services.AddSingleton<AuthCodeStore>();
builder.Services.AddSingleton<TestUserStore>();
builder.Services.AddSingleton<TokenService>();

var app = builder.Build();

app.MapMetadataEndpoints();
app.MapRegistrationEndpoints();
app.MapAuthorizeEndpoints();
app.MapTokenEndpoints();

// Surface the effective configuration at startup: nearly every failure in this rig traces back to
// a stale tunnel URL in PublicUrl or DefaultResource.
var options = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthServerOptions>>().Value;
app.Logger.LogInformation("Issuer (PublicUrl):  {Issuer}", options.PublicUrl);
app.Logger.LogInformation("Default resource:    {Resource}", options.DefaultResource);
app.Logger.LogInformation("Static client:       {ClientId}", options.SeedClient.ClientId);

app.Run();
