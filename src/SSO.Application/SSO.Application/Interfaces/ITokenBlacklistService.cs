namespace SSO.Application.Interfaces;

public interface ITokenBlacklistService
{
    Task<bool> IsTokenRevokedAsync(string token, CancellationToken cancellationToken = default);
    Task RevokeTokenAsync(string token, TimeSpan expiry, CancellationToken cancellationToken = default);
}
