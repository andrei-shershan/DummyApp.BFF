using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Yarp.ReverseProxy;
using DummyApp.BFF.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);

// load optional appsettings (contains ReverseProxy and OIDC placeholders)
builder.Configuration.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// Authentication: cookie for the browser session + OpenID Connect for the external identity provider.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "oidc";
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.Name = ".DummyApp.BFF.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    })
    .AddOpenIdConnect("oidc", options =>
    {
        // These values should be set in appsettings.json or user-secrets for your environment
        options.Authority = builder.Configuration["Authentication:Oidc:Authority"];
        options.ClientId = builder.Configuration["Authentication:Oidc:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Oidc:ClientSecret"];

        options.ResponseType = "code"; // Authorization Code
        options.UsePkce = true;         // PKCE
        options.SaveTokens = true;      // Temporarily keep tokens so we can capture them server-side in OnTokenValidated

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("offline_access");

        options.GetClaimsFromUserInfoEndpoint = true;

        // Capture tokens and move them to a server-side token store (in-memory for now).
        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = async ctx =>
            {
                try
                {
                    var access = ctx.Properties.GetTokenValue("access_token");
                    var refresh = ctx.Properties.GetTokenValue("refresh_token");
                    var expiresAtStr = ctx.Properties.GetTokenValue("expires_at");
                    DateTimeOffset expiresAt;

                    if (!string.IsNullOrEmpty(expiresAtStr) && DateTimeOffset.TryParse(expiresAtStr, out var parsed))
                    {
                        expiresAt = parsed;
                    }
                    else
                    {
                        var expiresInStr = ctx.Properties.GetTokenValue("expires_in");
                        var expiresIn = int.TryParse(expiresInStr, out var ei) ? ei : 3600;
                        expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                    }

                    var sessionId = Guid.NewGuid().ToString("N");

                    var store = ctx.HttpContext.RequestServices.GetRequiredService<ITokenStore>();
                    await store.StoreAsync(sessionId, new TokenSet
                    {
                        AccessToken = access ?? string.Empty,
                        RefreshToken = refresh,
                        ExpiresAt = expiresAt
                    });

                    // Remove tokens from the authentication properties so they are not persisted in the cookie
                    ctx.Properties.StoreTokens(new List<AuthenticationToken>());

                    // Write a small session cookie that refers to the server-side token set
                    ctx.HttpContext.Response.Cookies.Append(
                        ".DummyApp.BFF.Session",
                        sessionId,
                        new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Lax
                        });
                }
                catch
                {
                    // swallow - don't block sign-in on token store failures for this minimal example
                }
            }
        };
    });

// YARP - reverse proxy configuration loaded from configuration (appsettings.json)
builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

// Token store and service (in-memory for now)
builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();
builder.Services.AddHttpClient("token_client");
builder.Services.AddSingleton<ITokenService, TokenService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Middleware: attach access token from the authenticated user (if present) as Authorization header
// so YARP will forward it to downstream APIs. For a production system consider storing tokens
// in a server-side cache (ID, Redis) and avoid SaveTokens in the cookie.
app.Use(async (context, next) =>
{
    // Try to read session id cookie and resolve access token from the token service
    var sessionId = context.Request.Cookies[".DummyApp.BFF.Session"];
    if (!string.IsNullOrEmpty(sessionId))
    {
        var tokenService = context.RequestServices.GetRequiredService<ITokenService>();
        var access = await tokenService.GetAccessTokenAsync(sessionId);
        if (!string.IsNullOrEmpty(access))
        {
            context.Request.Headers["Authorization"] = "Bearer " + access;
        }
    }

    await next();
});

// Simple endpoints to start login/logout flows from the browser
app.MapGet("/login", async (HttpContext ctx) =>
{
    // Challenge the OIDC provider - will redirect the browser to the identity server
    await ctx.ChallengeAsync("oidc", new AuthenticationProperties { RedirectUri = "/" });
});

app.MapGet("/logout", async (HttpContext ctx) =>
{
    // Remove server-side tokens for this session
    var sessionId = ctx.Request.Cookies[".DummyApp.BFF.Session"];
    if (!string.IsNullOrEmpty(sessionId))
    {
        var tokenService = ctx.RequestServices.GetRequiredService<ITokenService>();
        await tokenService.RemoveAsync(sessionId);
        ctx.Response.Cookies.Delete(".DummyApp.BFF.Session");
    }

    // Sign out locally and at the identity provider
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync("oidc", new AuthenticationProperties { RedirectUri = "/" });
});

app.MapControllers();

// Map the reverse proxy (YARP) - it will handle routes configured in appsettings.json
app.MapReverseProxy();

app.Run();
