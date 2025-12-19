using Microsoft.EntityFrameworkCore;
using SSO.Application.Interfaces;
using SSO.Domain.Entities;

namespace SSO.Infrastructure.Persistence.Repositories;

public class SessionRepository : ISessionRepository
{
    private readonly SsoDbContext _context;

    public SessionRepository(SsoDbContext context)
    {
        _context = context;
    }

    public async Task<UserSession?> GetBySessionIdAsync(string sessionId, CancellationToken cancellationToken = default)
    {
        return await _context.UserSessions
            .Include(s => s.ApplicationTokens)
            .Include(s => s.User)
            .FirstOrDefaultAsync(s => s.SessionId == sessionId, cancellationToken);
    }

    public async Task<UserSession?> GetByUserIdAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        return await _context.UserSessions
            .Include(s => s.ApplicationTokens)
            .Include(s => s.User)
            .Where(s => s.UserId == userId && !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(s => s.CreatedAt)
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<UserSession> AddAsync(UserSession session, CancellationToken cancellationToken = default)
    {
        await _context.UserSessions.AddAsync(session, cancellationToken);
        return session;
    }

    public Task UpdateAsync(UserSession session, CancellationToken cancellationToken = default)
    {
        _context.UserSessions.Update(session);
        return Task.CompletedTask;
    }

    public async Task<ApplicationToken?> GetApplicationTokenAsync(string sessionId, string clientId, CancellationToken cancellationToken = default)
    {
        return await _context.ApplicationTokens
            .Include(t => t.UserSession)
            .FirstOrDefaultAsync(t => t.UserSession.SessionId == sessionId && t.ClientId == clientId, cancellationToken);
    }

    public async Task AddApplicationTokenAsync(ApplicationToken token, CancellationToken cancellationToken = default)
    {
        await _context.ApplicationTokens.AddAsync(token, cancellationToken);
    }

    public Task UpdateApplicationTokenAsync(ApplicationToken token, CancellationToken cancellationToken = default)
    {
        _context.ApplicationTokens.Update(token);
        return Task.CompletedTask;
    }
}
