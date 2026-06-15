using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using DummyApp.BFF.Configuration;
using DummyApp.BFF.Services;

namespace DummyApp.BFF.Extensions
{
    public static class BffServiceCollectionExtensions
    {
        public static WebApplicationBuilder AddBffServices(this WebApplicationBuilder builder)
        {
            builder.Services.Configure<ConfigurationSettings>(builder.Configuration);
            var configurationSettings = builder.Configuration.Get<ConfigurationSettings>() ?? new ConfigurationSettings();

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddOpenApi();

            var allowedOrigins = configurationSettings.Cors.AllowedOrigins;
            builder.Services.AddCors(options =>
            {
                options.AddPolicy(nameof(ConfigurationSettings.Cors), policy =>
                    policy.WithOrigins(allowedOrigins)
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials());
            });

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = ".DummyApp.BFF.Auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = configurationSettings.IdentityServer.Authority;
                options.RequireHttpsMetadata = true;
                options.ClientId = configurationSettings.IdentityServer.OidcClients.BFF.ClientId;
                options.ClientSecret = configurationSettings.IdentityServer.OidcClients.BFF.ClientSecret;

                options.ResponseType = "code";
                options.UsePkce = true;
                options.SaveTokens = true;

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("offline_access");

                options.GetClaimsFromUserInfoEndpoint = false;
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                options.NonceCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = ctx =>
                    {
                        var internalBase = configurationSettings.IdentityServer.MetadataAddress
                            ?.Replace("/.well-known/openid-configuration", "") ?? string.Empty;
                        var publicBase = configurationSettings.IdentityServer.Authority ?? string.Empty;

                        if (!string.IsNullOrEmpty(internalBase) && !string.IsNullOrEmpty(publicBase)
                            && ctx.ProtocolMessage.IssuerAddress.StartsWith(internalBase, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.ProtocolMessage.IssuerAddress =
                                publicBase.TrimEnd('/') +
                                ctx.ProtocolMessage.IssuerAddress[internalBase.TrimEnd('/').Length..];
                        }

                        ctx.ProtocolMessage.ResponseMode = "query";
                        return Task.CompletedTask;
                    },

                    OnRedirectToIdentityProviderForSignOut = ctx =>
                    {
                        var internalBase = configurationSettings.IdentityServer.MetadataAddress
                            ?.Replace("/.well-known/openid-configuration", "") ?? string.Empty;
                        var publicBase = configurationSettings.IdentityServer.Authority ?? string.Empty;

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

                            ctx.Properties.StoreTokens(new List<AuthenticationToken>());
                            ctx.HttpContext.Response.Cookies.Append(
                                ".DummyApp.BFF.Session",
                                sessionId,
                                new CookieOptions
                                {
                                    HttpOnly = true,
                                    Secure = true,
                                    SameSite = SameSiteMode.None
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

            builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection(nameof(ConfigurationSettings.ReverseProxy)));
            builder.Services.AddSingleton<ITokenStore, InMemoryTokenStore>();
            builder.Services.AddHttpClient("token_client");
            builder.Services.AddSingleton<ITokenService, TokenService>();

            return builder;
        }
    }
}
