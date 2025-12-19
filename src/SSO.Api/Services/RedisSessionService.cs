using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using sso.api.Configuration;
using sso.api.Models;

namespace sso.api.Services;

public class RedisSessionService : ISessionService
{
    private readonly IDistributedCache _cache;
    private readonly RedisSettings _settings;
    private const string SessionPrefix = "session:";
    private const string UserSessionPrefix = "user_session:";
    private const string RevokedTokenPrefix = "revoked_token:";

    public RedisSessionService(IDistributedCache cache, IOptions<RedisSettings> settings)
    {
        _cache = cache;
        _settings = settings.Value;
    }

    public async Task<UserSession> CreateSessionAsync(User user)
    {
        var session = new UserSession
        {
            SessionId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            Username = user.Username,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(_settings.SessionExpirationHours),
            IsRevoked = false,
            ApplicationTokens = []
        };

        await SaveSessionAsync(session);

        // Map user to session for quick lookup
        await _cache.SetStringAsync(
            $"{UserSessionPrefix}{user.Id}",
            session.SessionId,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = session.ExpiresAt
            });

        return session;
    }

    public async Task<UserSession?> GetSessionAsync(string sessionId)
    {
        var sessionJson = await _cache.GetStringAsync($"{SessionPrefix}{sessionId}");
        if (string.IsNullOrEmpty(sessionJson))
            return null;

        var session = JsonSerializer.Deserialize<UserSession>(sessionJson);
        if (session == null || session.IsRevoked || session.ExpiresAt < DateTime.UtcNow)
            return null;

        return session;
    }

    public async Task<UserSession?> GetSessionByUserIdAsync(Guid userId)
    {
        var sessionId = await _cache.GetStringAsync($"{UserSessionPrefix}{userId}");
        if (string.IsNullOrEmpty(sessionId))
            return null;

        return await GetSessionAsync(sessionId);
    }

    public async Task<bool> ValidateSessionAsync(string sessionId)
    {
        var session = await GetSessionAsync(sessionId);
        return session != null && !session.IsRevoked && session.ExpiresAt > DateTime.UtcNow;
    }

    public async Task AddApplicationTokenAsync(string sessionId, ApplicationToken token)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return;

        var existingToken = session.ApplicationTokens.FirstOrDefault(t => t.ClientId == token.ClientId);
        if (existingToken != null)
        {
            // Revoke old token before adding new one
            await RevokeTokenAsync(existingToken.AccessToken);
            session.ApplicationTokens.Remove(existingToken);
        }

        session.ApplicationTokens.Add(token);
        await SaveSessionAsync(session);
    }

    public async Task<ApplicationToken?> GetApplicationTokenAsync(string sessionId, string clientId)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return null;

        var token = session.ApplicationTokens.FirstOrDefault(t => t.ClientId == clientId);
        if (token == null || token.IsRevoked)
            return null;

        return token;
    }

    public async Task RevokeSessionAsync(string sessionId)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return;

        // Revoke all application tokens
        foreach (var token in session.ApplicationTokens)
        {
            await RevokeTokenAsync(token.AccessToken);
            token.IsRevoked = true;
        }

        session.IsRevoked = true;
        await SaveSessionAsync(session);

        // Remove user session mapping
        await _cache.RemoveAsync($"{UserSessionPrefix}{session.UserId}");
    }

    public async Task RevokeApplicationTokenAsync(string sessionId, string clientId)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return;

        var token = session.ApplicationTokens.FirstOrDefault(t => t.ClientId == clientId);
        if (token != null)
        {
            await RevokeTokenAsync(token.AccessToken);
            token.IsRevoked = true;
            await SaveSessionAsync(session);
        }
    }

    public async Task<bool> IsTokenRevokedAsync(string accessToken)
    {
        var revoked = await _cache.GetStringAsync($"{RevokedTokenPrefix}{accessToken}");
        return !string.IsNullOrEmpty(revoked);
    }

    public async Task RevokeTokenAsync(string accessToken)
    {
        await _cache.SetStringAsync(
            $"{RevokedTokenPrefix}{accessToken}",
            "revoked",
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(_settings.SessionExpirationHours)
            });
    }

    public async Task<List<string>> GetActiveSessionClientIdsAsync(string sessionId)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return [];

        return session.ApplicationTokens
            .Where(t => !t.IsRevoked && t.AccessTokenExpiresAt > DateTime.UtcNow)
            .Select(t => t.ClientId)
            .ToList();
    }

    private async Task SaveSessionAsync(UserSession session)
    {
        var sessionJson = JsonSerializer.Serialize(session);
        await _cache.SetStringAsync(
            $"{SessionPrefix}{session.SessionId}",
            sessionJson,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = session.ExpiresAt
            });
    }
}
