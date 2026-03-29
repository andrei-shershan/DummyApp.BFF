using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace DummyApp.BFF.Services
{
    public class InMemoryTokenStore : ITokenStore
    {
        private readonly ConcurrentDictionary<string, TokenSet> _store = new();

        public Task StoreAsync(string sessionId, TokenSet tokens)
        {
            _store[sessionId] = tokens;
            return Task.CompletedTask;
        }

        public Task<TokenSet?> GetAsync(string sessionId)
        {
            _store.TryGetValue(sessionId, out var tokens);
            return Task.FromResult(tokens);
        }

        public Task RemoveAsync(string sessionId)
        {
            _store.TryRemove(sessionId, out _);
            return Task.CompletedTask;
        }
    }
}
