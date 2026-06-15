using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using DummyApp.BFF.Configuration;

namespace DummyApp.BFF.Services
{
    public class TokenService : ITokenService
    {
        private readonly ITokenStore _store;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ConfigurationSettings _settings;
        private readonly ConcurrentDictionary<string, SemaphoreSlim> _refreshLocks = new();

        public TokenService(
            ITokenStore store,
            IHttpClientFactory httpClientFactory,
            IOptions<ConfigurationSettings> configuration)
        {
            _store = store;
            _httpClientFactory = httpClientFactory;
            _settings = configuration.Value;
        }

        public async Task<string?> GetAccessTokenAsync(string sessionId)
        {
            var tokens = await _store.GetAsync(sessionId);
            if (tokens == null)
            {
                return null;
            }

            if (tokens.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(60))
            {
                return tokens.AccessToken;
            }

            var refreshLock = _refreshLocks.GetOrAdd(sessionId, _ => new SemaphoreSlim(1, 1));
            await refreshLock.WaitAsync();
            try
            {
                tokens = await _store.GetAsync(sessionId);
                if (tokens == null)
                {
                    return null;
                }

                if (tokens.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(60))
                {
                    return tokens.AccessToken;
                }

                return await RefreshAsync(sessionId, tokens);
            }
            finally
            {
                refreshLock.Release();
            }
        }

        public Task RemoveAsync(string sessionId) => _store.RemoveAsync(sessionId);

        private async Task<string?> RefreshAsync(string sessionId, TokenSet tokens)
        {
            if (string.IsNullOrEmpty(tokens.RefreshToken))
            {
                await _store.RemoveAsync(sessionId);
                return null;
            }

            var client = _httpClientFactory.CreateClient("token_client");
            var tokenEndpoint = _settings.IdentityServer.OidcClients.BFF.TokenEndpoint
                ?? _settings.IdentityServer.Authority.TrimEnd('/') + "/connect/token";

            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = tokens.RefreshToken,
                ["client_id"] = _settings.IdentityServer.OidcClients.BFF.ClientId,
                ["client_secret"] = _settings.IdentityServer.OidcClients.BFF.ClientSecret,
            };

            var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(parameters)
            };

            HttpResponseMessage resp;
            try
            {
                resp = await client.SendAsync(req);
            }
            catch
            {
                return null;
            }

            if (!resp.IsSuccessStatusCode)
            {
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
