using System.Collections.Concurrent;
using System.Security.Cryptography;
using sso.api.Models;

namespace sso.api.Services;

public class UserService : IUserService
{
    private static readonly ConcurrentDictionary<Guid, User> _users = new();

    public Task<User?> GetByIdAsync(Guid id)
    {
        _users.TryGetValue(id, out var user);
        return Task.FromResult(user);
    }

    public Task<User?> GetByUsernameAsync(string username)
    {
        var user = _users.Values.FirstOrDefault(u =>
            u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(user);
    }

    public Task<User?> GetByRefreshTokenAsync(string refreshToken)
    {
        var user = _users.Values.FirstOrDefault(u =>
            u.RefreshToken == refreshToken &&
            u.RefreshTokenExpiryTime > DateTime.UtcNow);
        return Task.FromResult(user);
    }

    public Task<User> CreateAsync(string username, string email, string password)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = username,
            Email = email,
            PasswordHash = HashPassword(password),
            Roles = ["User"],
            CreatedAt = DateTime.UtcNow
        };

        _users.TryAdd(user.Id, user);
        return Task.FromResult(user);
    }

    public Task<bool> ValidatePasswordAsync(User user, string password)
    {
        var result = VerifyPassword(password, user.PasswordHash);
        return Task.FromResult(result);
    }

    public Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime)
    {
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = expiryTime;
        return Task.CompletedTask;
    }

    public Task RevokeRefreshTokenAsync(User user)
    {
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        return Task.CompletedTask;
    }

    public Task UpdateLastLoginAsync(User user)
    {
        user.LastLoginAt = DateTime.UtcNow;
        return Task.CompletedTask;
    }

    private static string HashPassword(string password)
    {
        var salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);

        var hashBytes = new byte[48];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 32);

        return Convert.ToBase64String(hashBytes);
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var hashBytes = Convert.FromBase64String(storedHash);

        var salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);

        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);

        for (int i = 0; i < 32; i++)
        {
            if (hashBytes[i + 16] != hash[i])
                return false;
        }

        return true;
    }
}
