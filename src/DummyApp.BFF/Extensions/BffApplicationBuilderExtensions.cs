using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using DummyApp.BFF.Configuration;
using DummyApp.BFF.Services;

namespace DummyApp.BFF.Extensions
{
    public static class BffApplicationBuilderExtensions
    {
        public static WebApplication UseBff(this WebApplication app)
        {
            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.MapOpenApi();
            }

            var configuration = app.Services.GetRequiredService<IOptions<ConfigurationSettings>>().Value;
            var forwardedOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };

            if (configuration.ReverseProxy.TrustAllProxies)
            {
                forwardedOptions.KnownNetworks.Clear();
                forwardedOptions.KnownProxies.Clear();
            }

            app.UseForwardedHeaders(forwardedOptions);
            app.UseHttpsRedirection();
            app.UseCors(nameof(ConfigurationSettings.Cors));
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseTokenForwarding();
            app.MapAuthRoutes();
            app.MapControllers();
            app.MapReverseProxy();

            return app;
        }

        public static IApplicationBuilder UseTokenForwarding(this IApplicationBuilder app)
        {
            return app.Use(async (context, next) =>
            {
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
        }

        public static IEndpointRouteBuilder MapAuthRoutes(this IEndpointRouteBuilder endpoints)
        {
            var config = endpoints.ServiceProvider.GetRequiredService<IOptions<ConfigurationSettings>>().Value;
            var frontendUrl = config.Services.Frontend.BaseUrl;

            endpoints.MapGet("/login", async (HttpContext ctx) =>
            {
                await ctx.ChallengeAsync("oidc", new AuthenticationProperties { RedirectUri = frontendUrl });
            });

            endpoints.MapGet("/logout", async (HttpContext ctx) =>
            {
                var sessionId = ctx.Request.Cookies[".DummyApp.BFF.Session"];
                if (!string.IsNullOrEmpty(sessionId))
                {
                    var tokenService = ctx.RequestServices.GetRequiredService<ITokenService>();
                    await tokenService.RemoveAsync(sessionId);
                    ctx.Response.Cookies.Delete(".DummyApp.BFF.Session");
                }

                await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await ctx.SignOutAsync("oidc", new AuthenticationProperties { RedirectUri = frontendUrl });
            });

            endpoints.MapGet("/me", (HttpContext ctx) =>
            {
                if (ctx.User.Identity?.IsAuthenticated != true)
                    return Results.Json(new { isAuthenticated = false });

                var sub = ctx.User.FindFirst("sub")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var name = ctx.User.FindFirst("name")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.Name)?.Value;
                var email = ctx.User.FindFirst("email")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.Email)?.Value;
                var roles = ctx.User.FindAll("role")
                    .Concat(ctx.User.FindAll(ClaimTypes.Role))
                    .Select(c => c.Value)
                    .Distinct()
                    .ToArray();

                return Results.Json(new { isAuthenticated = true, sub, name, email, roles });
            });

            return endpoints;
        }
    }
}
