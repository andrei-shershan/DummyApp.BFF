using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace DummyApp.BFF.Services
{
    public class TokenService : ITokenService
    {
        private readonly ITokenStore _store;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly object _lock = new();

        public TokenService(ITokenStore store, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _store = store;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        public async Task<string?> GetAccessTokenAsync(string sessionId)
        {
            var tokens = await _store.GetAsync(sessionId);
            if (tokens == null) return null;

            // If token is still valid, return it
            if (tokens.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(60))
            {
                return tokens.AccessToken;
            }

            // Otherwise try refresh
            // Use a lock per service instance to avoid concurrent refreshes for the same session
            lock (_lock)
            {
                // Reload inside lock
                tokens = _store.GetAsync(sessionId).GetAwaiter().GetResult();
                if (tokens == null) return null;
                if (tokens.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(60)) return tokens.AccessToken;

                // perform refresh synchronously inside lock
                var refreshed = RefreshAsync(sessionId, tokens).GetAwaiter().GetResult();
                return refreshed;
            }
        }

        public Task RemoveAsync(string sessionId)
        {
            return _store.RemoveAsync(sessionId);
        }

        private async Task<string?> RefreshAsync(string sessionId, TokenSet tokens)
        {
            var client = _httpClientFactory.CreateClient("token_client");
            var tokenEndpoint = _configuration["Authentication:Oidc:TokenEndpoint"] ?? _configuration["Authentication:Oidc:Authority"] + "/connect/token";

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = tokens.RefreshToken ?? string.Empty,
                ["client_id"] = _configuration["Authentication:Oidc:ClientId"],
                ["client_secret"] = _configuration["Authentication:Oidc:ClientSecret"],
            };

            var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(parameters)
            };

            var resp = await client.SendAsync(req);
            if (!resp.IsSuccessStatusCode)
            {
                // failed refresh - remove tokens
                await _store.RemoveAsync(sessionId);
                return null;
            }

            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(stream);
            var root = doc.RootElement;

            var access = root.GetProperty("access_token").GetString() ?? string.Empty;
            var refresh = root.TryGetProperty("refresh_token", out var r) ? r.GetString() : tokens.RefreshToken;
            var expiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 3600;

            var newSet = new TokenSet
            {
                AccessToken = access,
                RefreshToken = refresh,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            await _store.StoreAsync(sessionId, newSet);
            return newSet.AccessToken;
        }
    }
}
