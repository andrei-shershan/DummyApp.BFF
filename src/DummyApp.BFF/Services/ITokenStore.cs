using System.Threading.Tasks;

namespace DummyApp.BFF.Services
{
    public interface ITokenStore
    {
        Task StoreAsync(string sessionId, TokenSet tokens);
        Task<TokenSet?> GetAsync(string sessionId);
        Task RemoveAsync(string sessionId);
    }
}
