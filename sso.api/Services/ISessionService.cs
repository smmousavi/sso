using sso.api.Models;

namespace sso.api.Services;

public interface ISessionService
{
    Task<UserSession> CreateSessionAsync(User user);
    Task<UserSession?> GetSessionAsync(string sessionId);
    Task<UserSession?> GetSessionByUserIdAsync(Guid userId);
    Task<bool> ValidateSessionAsync(string sessionId);
    Task AddApplicationTokenAsync(string sessionId, ApplicationToken token);
    Task<ApplicationToken?> GetApplicationTokenAsync(string sessionId, string clientId);
    Task RevokeSessionAsync(string sessionId);
    Task RevokeApplicationTokenAsync(string sessionId, string clientId);
    Task<bool> IsTokenRevokedAsync(string accessToken);
    Task RevokeTokenAsync(string accessToken);
    Task<List<string>> GetActiveSessionClientIdsAsync(string sessionId);
}
