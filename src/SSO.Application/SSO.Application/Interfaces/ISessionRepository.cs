using SSO.Domain.Entities;

namespace SSO.Application.Interfaces;

public interface ISessionRepository
{
    Task<UserSession?> GetBySessionIdAsync(string sessionId, CancellationToken cancellationToken = default);
    Task<UserSession?> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<UserSession> AddAsync(UserSession session, CancellationToken cancellationToken = default);
    Task UpdateAsync(UserSession session, CancellationToken cancellationToken = default);
    Task<ApplicationToken?> GetApplicationTokenAsync(string sessionId, string clientId, CancellationToken cancellationToken = default);
    Task AddApplicationTokenAsync(ApplicationToken token, CancellationToken cancellationToken = default);
    Task UpdateApplicationTokenAsync(ApplicationToken token, CancellationToken cancellationToken = default);
}
