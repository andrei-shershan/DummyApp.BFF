using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Yarp.ReverseProxy;
using DummyApp.BFF.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();
// CORS: allow the frontend origin to call the BFF
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFE", policy =>
        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials());
});

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
        options.RequireHttpsMetadata = true;
        options.ClientId = builder.Configuration["Authentication:Oidc:ClientId"];
        options.ClientSecret = builder.Configuration["Authentication:Oidc:ClientSecret"];

        options.ResponseType = "code"; // Authorization Code
        options.UsePkce = true;         // PKCE
        options.SaveTokens = true;      // Temporarily keep tokens so we can capture them server-side in OnTokenValidated

        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("offline_access");

        options.GetClaimsFromUserInfoEndpoint = false; // claims are in the ID token

        // Use GET redirect (query) instead of form_post.
        // form_post is a cross-site POST which SameSite=Lax cookies won't follow on HTTP.
        // query mode = GET redirect, which SameSite=Lax allows for top-level navigations.
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;

        // Capture tokens and move them to a server-side token store (in-memory for now).
        options.Events = new OpenIdConnectEvents
        {
            // The discovery document is fetched via the internal Docker address (identity:8080),
            // so authorization_endpoint may contain that internal host.
            // The browser cannot reach Docker-internal hostnames, so we rewrite to the public URL
            // before issuing the redirect.
            OnRedirectToIdentityProvider = ctx =>
            {
                var internalBase = builder.Configuration["Authentication:Oidc:MetadataAddress"]
                    ?.Replace("/.well-known/openid-configuration", "") ?? string.Empty;
                var publicBase = builder.Configuration["Authentication:Oidc:Authority"] ?? string.Empty;

                if (!string.IsNullOrEmpty(internalBase) && !string.IsNullOrEmpty(publicBase)
                    && ctx.ProtocolMessage.IssuerAddress.StartsWith(internalBase, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.ProtocolMessage.IssuerAddress =
                        publicBase.TrimEnd('/') +
                        ctx.ProtocolMessage.IssuerAddress[internalBase.TrimEnd('/').Length..];
                }

                // Force GET redirect so SameSite=Lax correlation cookies are sent back.
                ctx.ProtocolMessage.ResponseMode = "query";

                return Task.CompletedTask;
            },

            OnRedirectToIdentityProviderForSignOut = ctx =>
            {
                var internalBase = builder.Configuration["Authentication:Oidc:MetadataAddress"]
                    ?.Replace("/.well-known/openid-configuration", "") ?? string.Empty;
                var publicBase = builder.Configuration["Authentication:Oidc:Authority"] ?? string.Empty;

                if (!string.IsNullOrEmpty(internalBase) && !string.IsNullOrEmpty(publicBase)
                    && ctx.ProtocolMessage.IssuerAddress.StartsWith(internalBase, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.ProtocolMessage.IssuerAddress =
                        publicBase.TrimEnd('/') +
                        ctx.ProtocolMessage.IssuerAddress[internalBase.TrimEnd('/').Length..];
                }

                return Task.CompletedTask;
            },

            OnTokenValidated = async ctx =>
            {
                var logger = ctx.HttpContext.RequestServices
                    .GetRequiredService<ILoggerFactory>().CreateLogger("BFF.TokenCapture");
                try
                {
                    // ctx.TokenEndpointResponse is the raw response from /connect/token.
                    // It is always populated for authorization_code flow and is available
                    // BEFORE Properties tokens are written, so we read from here instead of
                    // ctx.Properties.GetTokenValue() which is null at this point in the pipeline.
                    var tokenResponse = ctx.TokenEndpointResponse;
                    var access = tokenResponse?.AccessToken;
                    var refresh = tokenResponse?.RefreshToken;

                    if (string.IsNullOrEmpty(access))
                    {
                        logger.LogWarning("OnTokenValidated: access_token missing in TokenEndpointResponse – session will not be stored.");
                        return;
                    }

                    var expiresIn = int.TryParse(tokenResponse?.ExpiresIn, out var ei) ? ei : 3600;
                    var expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

                    var sessionId = Guid.NewGuid().ToString("N");

                    var store = ctx.HttpContext.RequestServices.GetRequiredService<ITokenStore>();
                    await store.StoreAsync(sessionId, new TokenSet
                    {
                        AccessToken = access,
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

                    logger.LogInformation("Session {SessionId} stored, token expires at {ExpiresAt}", sessionId, expiresAt);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to capture tokens in OnTokenValidated");
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
// Temporary: enable Developer Exception Page in all environments
app.UseDeveloperExceptionPage();
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

var forwardedOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};
if (builder.Configuration.GetValue<bool>("ReverseProxy:TrustAllProxies"))
{
    // Required both in local Docker (Traefik) and on Azure App Service Linux,
    // where Azure's own front-end proxy forwards X-Forwarded-For / X-Forwarded-Proto.
    // Set ReverseProxy__TrustAllProxies=true in App Service Configuration for every environment.
    forwardedOptions.KnownNetworks.Clear();
    forwardedOptions.KnownProxies.Clear();
}
app.UseForwardedHeaders(forwardedOptions);
app.UseHttpsRedirection();

// Enable CORS early so preflight (OPTIONS) requests are handled before auth
app.UseCors("AllowFE");

app.UseAuthentication();
app.UseAuthorization();

// Middleware: attach access token from the authenticated user (if present) as Authorization header
// so YARP will forward it to downstream APIs. For a production system consider storing tokens
// in a server-side cache (ID, Redis) and avoid SaveTokens in the cookie.
app.Use(async (context, next) =>
{
    // Try to read session id cookie and resolve access token from the token service
    var sessionId = context.Request.Cookies[".DummyApp.BFF.Session"];
    System.Console.WriteLine($"Session ID from cookie: {sessionId}");
    if (!string.IsNullOrEmpty(sessionId))
    {
        var tokenService = context.RequestServices.GetRequiredService<ITokenService>();
        var access = await tokenService.GetAccessTokenAsync(sessionId);
        System.Console.WriteLine($"Access token for session {sessionId}: {(string.IsNullOrEmpty(access) ? "null or empty" : access[..10] + "...")}");
        if (!string.IsNullOrEmpty(access))
        {
            context.Request.Headers["Authorization"] = "Bearer " + access;
        }
    }

    await next();
});

// Simple endpoints to start login/logout flows from the browser
var frontendUrl = builder.Configuration["App:FrontendUrl"] ?? "/";

app.MapGet("/login", async (HttpContext ctx) =>
{
    // Challenge the OIDC provider - will redirect the browser to the identity server
    await ctx.ChallengeAsync("oidc", new AuthenticationProperties { RedirectUri = frontendUrl });
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
    await ctx.SignOutAsync("oidc", new AuthenticationProperties { RedirectUri = frontendUrl });
});

app.MapControllers();

// /me – returns the authenticated user's basic info so the frontend can
// show the login state without storing any token in the browser.
app.MapGet("/me", (HttpContext ctx) =>
{
    if (ctx.User.Identity?.IsAuthenticated != true)
        return Results.Json(new { isAuthenticated = false });

    var sub = ctx.User.FindFirst("sub")?.Value
        ?? ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    var name = ctx.User.FindFirst("name")?.Value
        ?? ctx.User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
    var email = ctx.User.FindFirst("email")?.Value
        ?? ctx.User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

    return Results.Json(new { isAuthenticated = true, sub, name, email });
});

// Map the reverse proxy (YARP) - it will handle routes configured in appsettings.json
app.MapReverseProxy();

app.Run();
