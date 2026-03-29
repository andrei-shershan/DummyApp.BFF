using System.Threading.Tasks;

namespace DummyApp.BFF.Services
{
    public interface ITokenService
    {
        Task<string?> GetAccessTokenAsync(string sessionId);
        Task RemoveAsync(string sessionId);
    }
}
