using System.Security.Claims;
using SSO.Domain.Entities;

namespace SSO.Application.Interfaces;

public interface ITokenService
{
    string GenerateAccessToken(User user, string? clientId = null, string? sessionId = null);
    string GenerateRefreshToken();
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
    ClaimsPrincipal? ValidateToken(string token);
    string? GetSessionIdFromToken(string token);
    string? GetClientIdFromToken(string token);
    Guid? GetUserIdFromToken(string token);
}
