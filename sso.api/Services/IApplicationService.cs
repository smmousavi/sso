using sso.api.Models;

namespace sso.api.Services;

public interface IApplicationService
{
    Task<ClientApplication> RegisterAsync(string name, string[]? scopes, string[]? redirectUris);
    Task<ClientApplication?> GetByClientIdAsync(string clientId);
    Task<bool> ValidateClientAsync(string clientId, string clientSecret);
    Task<IEnumerable<ClientApplication>> GetAllAsync();
    Task<bool> DeactivateAsync(string clientId);
}
