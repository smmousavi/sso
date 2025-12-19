using SSO.Application.Interfaces;
using SSO.Domain.Entities;

namespace SSO.Application.Services;

public class SessionService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly ITokenBlacklistService _tokenBlacklist;
    private readonly int _sessionExpirationHours;

    public SessionService(IUnitOfWork unitOfWork, ITokenBlacklistService tokenBlacklist, int sessionExpirationHours = 24)
    {
        _unitOfWork = unitOfWork;
        _tokenBlacklist = tokenBlacklist;
        _sessionExpirationHours = sessionExpirationHours;
    }

    public async Task<UserSession> CreateSessionAsync(User user, CancellationToken cancellationToken = default)
    {
        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            SessionId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(_sessionExpirationHours),
            IsRevoked = false
        };

        await _unitOfWork.Sessions.AddAsync(session, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return session;
    }

    public async Task<UserSession?> GetSessionAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _unitOfWork.Sessions.GetBySessionIdAsync(sessionId, cancellationToken);
        if (session == null || session.IsRevoked || session.ExpiresAt < DateTime.UtcNow)
            return null;

        return session;
    }

    public async Task<UserSession?> GetSessionByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var session = await _unitOfWork.Sessions.GetByUserIdAsync(userId, cancellationToken);
        if (session == null || session.IsRevoked || session.ExpiresAt < DateTime.UtcNow)
            return null;

        return session;
    }

    public async Task<bool> ValidateSessionAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var session = await GetSessionAsync(sessionId, cancellationToken);
        return session != null;
    }

    public async Task AddApplicationTokenAsync(string sessionId, ApplicationToken token, CancellationToken cancellationToken = default)
    {
        var session = await _unitOfWork.Sessions.GetBySessionIdAsync(sessionId, cancellationToken);
        if (session == null)
            return;

        var existingToken = await _unitOfWork.Sessions.GetApplicationTokenAsync(sessionId, token.ClientId, cancellationToken);
        if (existingToken != null)
        {
            await _tokenBlacklist.RevokeTokenAsync(existingToken.AccessToken, TimeSpan.FromHours(_sessionExpirationHours), cancellationToken);
            existingToken.IsRevoked = true;
            await _unitOfWork.Sessions.UpdateApplicationTokenAsync(existingToken, cancellationToken);
        }

        token.Id = Guid.NewGuid();
        token.UserSessionId = session.Id;
        token.CreatedAt = DateTime.UtcNow;
        await _unitOfWork.Sessions.AddApplicationTokenAsync(token, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task<ApplicationToken?> GetApplicationTokenAsync(string sessionId, string clientId, CancellationToken cancellationToken = default)
    {
        var token = await _unitOfWork.Sessions.GetApplicationTokenAsync(sessionId, clientId, cancellationToken);
        if (token == null || token.IsRevoked)
            return null;

        return token;
    }

    public async Task RevokeSessionAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _unitOfWork.Sessions.GetBySessionIdAsync(sessionId, cancellationToken);
        if (session == null)
            return;

        foreach (var token in session.ApplicationTokens)
        {
            await _tokenBlacklist.RevokeTokenAsync(token.AccessToken, TimeSpan.FromHours(_sessionExpirationHours), cancellationToken);
            token.IsRevoked = true;
            await _unitOfWork.Sessions.UpdateApplicationTokenAsync(token, cancellationToken);
        }

        session.IsRevoked = true;
        await _unitOfWork.Sessions.UpdateAsync(session, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeApplicationTokenAsync(string sessionId, string clientId, CancellationToken cancellationToken = default)
    {
        var token = await _unitOfWork.Sessions.GetApplicationTokenAsync(sessionId, clientId, cancellationToken);
        if (token != null)
        {
            await _tokenBlacklist.RevokeTokenAsync(token.AccessToken, TimeSpan.FromHours(_sessionExpirationHours), cancellationToken);
            token.IsRevoked = true;
            await _unitOfWork.Sessions.UpdateApplicationTokenAsync(token, cancellationToken);
            await _unitOfWork.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<bool> IsTokenRevokedAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        return await _tokenBlacklist.IsTokenRevokedAsync(accessToken, cancellationToken);
    }

    public async Task RevokeTokenAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        await _tokenBlacklist.RevokeTokenAsync(accessToken, TimeSpan.FromHours(_sessionExpirationHours), cancellationToken);
    }

    public async Task<List<string>> GetActiveSessionClientIdsAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _unitOfWork.Sessions.GetBySessionIdAsync(sessionId, cancellationToken);
        if (session == null)
            return [];

        return session.ApplicationTokens
            .Where(t => !t.IsRevoked && t.AccessTokenExpiresAt > DateTime.UtcNow)
            .Select(t => t.ClientId)
            .ToList();
    }
}
