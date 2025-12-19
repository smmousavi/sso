using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using sso.api.Models;

namespace sso.api.Services;

public class UserService : IUserService
{
    private readonly IDistributedCache _cache;
    private const string UserPrefix = "user:";
    private const string UsernameIndexPrefix = "user_username:";
    private const string EmailIndexPrefix = "user_email:";
    private const string AllUsersKey = "users:all";

    public UserService(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task<User?> GetByIdAsync(Guid id)
    {
        var userJson = await _cache.GetStringAsync($"{UserPrefix}{id}");
        if (string.IsNullOrEmpty(userJson))
            return null;

        return JsonSerializer.Deserialize<User>(userJson);
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        var userId = await _cache.GetStringAsync($"{UsernameIndexPrefix}{username.ToLowerInvariant()}");
        if (string.IsNullOrEmpty(userId))
            return null;

        return await GetByIdAsync(Guid.Parse(userId));
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        var userId = await _cache.GetStringAsync($"{EmailIndexPrefix}{email.ToLowerInvariant()}");
        if (string.IsNullOrEmpty(userId))
            return null;

        return await GetByIdAsync(Guid.Parse(userId));
    }

    public async Task<User?> GetByRefreshTokenAsync(string refreshToken)
    {
        var users = await GetAllAsync();
        return users.FirstOrDefault(u =>
            u.RefreshToken == refreshToken &&
            u.RefreshTokenExpiryTime > DateTime.UtcNow);
    }

    public async Task<IEnumerable<User>> GetAllAsync()
    {
        var userIdsJson = await _cache.GetStringAsync(AllUsersKey);
        if (string.IsNullOrEmpty(userIdsJson))
            return [];

        var userIds = JsonSerializer.Deserialize<List<Guid>>(userIdsJson) ?? [];
        var users = new List<User>();

        foreach (var id in userIds)
        {
            var user = await GetByIdAsync(id);
            if (user != null)
                users.Add(user);
        }

        return users;
    }

    public async Task<User> CreateAsync(string username, string email, string password)
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

        await SaveUserAsync(user);

        // Create username index
        await _cache.SetStringAsync(
            $"{UsernameIndexPrefix}{username.ToLowerInvariant()}",
            user.Id.ToString());

        // Create email index
        await _cache.SetStringAsync(
            $"{EmailIndexPrefix}{email.ToLowerInvariant()}",
            user.Id.ToString());

        // Add to all users list
        await AddToUserListAsync(user.Id);

        return user;
    }

    public Task<bool> ValidatePasswordAsync(User user, string password)
    {
        var result = VerifyPassword(password, user.PasswordHash);
        return Task.FromResult(result);
    }

    public async Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime)
    {
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = expiryTime;
        await SaveUserAsync(user);
    }

    public async Task RevokeRefreshTokenAsync(User user)
    {
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await SaveUserAsync(user);
    }

    public async Task UpdateLastLoginAsync(User user)
    {
        user.LastLoginAt = DateTime.UtcNow;
        await SaveUserAsync(user);
    }

    public async Task UpdateRolesAsync(User user, string[] roles)
    {
        user.Roles = roles;
        await SaveUserAsync(user);
    }

    public async Task<bool> DeleteAsync(Guid id)
    {
        var user = await GetByIdAsync(id);
        if (user == null)
            return false;

        // Remove user
        await _cache.RemoveAsync($"{UserPrefix}{id}");

        // Remove username index
        await _cache.RemoveAsync($"{UsernameIndexPrefix}{user.Username.ToLowerInvariant()}");

        // Remove email index
        await _cache.RemoveAsync($"{EmailIndexPrefix}{user.Email.ToLowerInvariant()}");

        // Remove from all users list
        await RemoveFromUserListAsync(id);

        return true;
    }

    private async Task SaveUserAsync(User user)
    {
        var userJson = JsonSerializer.Serialize(user);
        await _cache.SetStringAsync($"{UserPrefix}{user.Id}", userJson);
    }

    private async Task AddToUserListAsync(Guid userId)
    {
        var userIdsJson = await _cache.GetStringAsync(AllUsersKey);
        var userIds = string.IsNullOrEmpty(userIdsJson)
            ? new List<Guid>()
            : JsonSerializer.Deserialize<List<Guid>>(userIdsJson) ?? [];

        if (!userIds.Contains(userId))
        {
            userIds.Add(userId);
            await _cache.SetStringAsync(AllUsersKey, JsonSerializer.Serialize(userIds));
        }
    }

    private async Task RemoveFromUserListAsync(Guid userId)
    {
        var userIdsJson = await _cache.GetStringAsync(AllUsersKey);
        if (string.IsNullOrEmpty(userIdsJson))
            return;

        var userIds = JsonSerializer.Deserialize<List<Guid>>(userIdsJson) ?? [];
        userIds.Remove(userId);
        await _cache.SetStringAsync(AllUsersKey, JsonSerializer.Serialize(userIds));
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
