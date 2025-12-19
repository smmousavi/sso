using System.Security.Cryptography;
using sso.api.Models;
using SSO.Application.Interfaces;

namespace sso.api.Services;

public class UserService : IUserService
{
    private readonly IUnitOfWork _unitOfWork;

    public UserService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    public async Task<User?> GetByIdAsync(Guid id)
    {
        var user = await _unitOfWork.Users.GetByIdAsync(id);
        if (user == null || !user.IsActive)
            return null;

        return MapToApiModel(user);
    }

    public async Task<User?> GetByUsernameAsync(string username)
    {
        var user = await _unitOfWork.Users.GetByUsernameAsync(username);
        if (user == null || !user.IsActive)
            return null;

        return MapToApiModel(user);
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        var user = await _unitOfWork.Users.GetByEmailAsync(email);
        if (user == null || !user.IsActive)
            return null;

        return MapToApiModel(user);
    }

    public async Task<User?> GetByRefreshTokenAsync(string refreshToken)
    {
        var users = await _unitOfWork.Users.GetAllAsync();
        var user = users.FirstOrDefault(u =>
            u.RefreshToken == refreshToken &&
            u.RefreshTokenExpiryTime > DateTime.UtcNow &&
            u.IsActive);

        return user != null ? MapToApiModel(user) : null;
    }

    public async Task<IEnumerable<User>> GetAllAsync()
    {
        var users = await _unitOfWork.Users.GetAllAsync();
        return users.Select(MapToApiModel);
    }

    public async Task<User> CreateAsync(string username, string email, string password)
    {
        var user = new SSO.Domain.Entities.User
        {
            Id = Guid.NewGuid(),
            Username = username,
            Email = email,
            PasswordHash = HashPassword(password),
            Roles = ["User"],
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _unitOfWork.Users.AddAsync(user);
        await _unitOfWork.SaveChangesAsync();

        return MapToApiModel(user);
    }

    public Task<bool> ValidatePasswordAsync(User user, string password)
    {
        var result = VerifyPassword(password, user.PasswordHash);
        return Task.FromResult(result);
    }

    public async Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime)
    {
        var domainUser = await _unitOfWork.Users.GetByIdAsync(user.Id);
        if (domainUser != null)
        {
            domainUser.RefreshToken = refreshToken;
            domainUser.RefreshTokenExpiryTime = expiryTime;
            await _unitOfWork.Users.UpdateAsync(domainUser);
            await _unitOfWork.SaveChangesAsync();
        }
    }

    public async Task RevokeRefreshTokenAsync(User user)
    {
        var domainUser = await _unitOfWork.Users.GetByIdAsync(user.Id);
        if (domainUser != null)
        {
            domainUser.RefreshToken = null;
            domainUser.RefreshTokenExpiryTime = null;
            await _unitOfWork.Users.UpdateAsync(domainUser);
            await _unitOfWork.SaveChangesAsync();
        }
    }

    public async Task UpdateLastLoginAsync(User user)
    {
        var domainUser = await _unitOfWork.Users.GetByIdAsync(user.Id);
        if (domainUser != null)
        {
            domainUser.LastLoginAt = DateTime.UtcNow;
            await _unitOfWork.Users.UpdateAsync(domainUser);
            await _unitOfWork.SaveChangesAsync();
        }
    }

    public async Task UpdateRolesAsync(User user, string[] roles)
    {
        var domainUser = await _unitOfWork.Users.GetByIdAsync(user.Id);
        if (domainUser != null)
        {
            domainUser.Roles = roles;
            await _unitOfWork.Users.UpdateAsync(domainUser);
            await _unitOfWork.SaveChangesAsync();
        }
    }

    public async Task<bool> DeleteAsync(Guid id)
    {
        var user = await _unitOfWork.Users.GetByIdAsync(id);
        if (user == null)
            return false;

        await _unitOfWork.Users.DeleteAsync(id);
        await _unitOfWork.SaveChangesAsync();
        return true;
    }

    private static User MapToApiModel(SSO.Domain.Entities.User domainUser)
    {
        return new User
        {
            Id = domainUser.Id,
            Username = domainUser.Username,
            Email = domainUser.Email,
            PasswordHash = domainUser.PasswordHash,
            Roles = domainUser.Roles,
            RefreshToken = domainUser.RefreshToken,
            RefreshTokenExpiryTime = domainUser.RefreshTokenExpiryTime,
            CreatedAt = domainUser.CreatedAt,
            LastLoginAt = domainUser.LastLoginAt
        };
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

