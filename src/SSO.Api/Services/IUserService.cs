using sso.api.Models;

namespace sso.api.Services;

public interface IUserService
{
    Task<User?> GetByIdAsync(Guid id);
    Task<User?> GetByUsernameAsync(string username);
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByRefreshTokenAsync(string refreshToken);
    Task<IEnumerable<User>> GetAllAsync();
    Task<User> CreateAsync(string username, string email, string password);
    Task<bool> ValidatePasswordAsync(User user, string password);
    Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime);
    Task RevokeRefreshTokenAsync(User user);
    Task UpdateLastLoginAsync(User user);
    Task UpdateRolesAsync(User user, string[] roles);
    Task<bool> DeleteAsync(Guid id);
}
