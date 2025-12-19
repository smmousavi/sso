using sso.api.Models;

namespace sso.api.Services;

public interface IUserService
{
    Task<User?> GetByIdAsync(Guid id);
    Task<User?> GetByUsernameAsync(string username);
    Task<User?> GetByRefreshTokenAsync(string refreshToken);
    Task<User> CreateAsync(string username, string email, string password);
    Task<bool> ValidatePasswordAsync(User user, string password);
    Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime);
    Task RevokeRefreshTokenAsync(User user);
    Task UpdateLastLoginAsync(User user);
}
