using SSO.Application.DTOs;
using SSO.Application.Interfaces;
using SSO.Domain.Entities;

namespace SSO.Application.Services;

public class UserService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _passwordHasher;

    public UserService(IUnitOfWork unitOfWork, IPasswordHasher passwordHasher)
    {
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
    }

    public async Task<UserResponse> RegisterAsync(RegisterUserRequest request, CancellationToken cancellationToken = default)
    {
        var existingUsername = await _unitOfWork.Users.GetByUsernameAsync(request.Username, cancellationToken);
        if (existingUsername != null)
        {
            return new UserResponse(false, "Username already exists", null);
        }

        var existingEmail = await _unitOfWork.Users.GetByEmailAsync(request.Email, cancellationToken);
        if (existingEmail != null)
        {
            return new UserResponse(false, "Email already exists", null);
        }

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = request.Username,
            Email = request.Email,
            PasswordHash = _passwordHasher.HashPassword(request.Password),
            Roles = ["User"],
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _unitOfWork.Users.AddAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return new UserResponse(true, "User registered successfully", new UserDto(user.Id, user.Username, user.Email, user.Roles));
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _unitOfWork.Users.GetByIdAsync(id, cancellationToken);
    }

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        return await _unitOfWork.Users.GetByUsernameAsync(username, cancellationToken);
    }

    public async Task<IEnumerable<User>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _unitOfWork.Users.GetAllAsync(cancellationToken);
    }

    public async Task<bool> ValidatePasswordAsync(User user, string password)
    {
        return _passwordHasher.VerifyPassword(password, user.PasswordHash);
    }

    public async Task UpdateRefreshTokenAsync(User user, string refreshToken, DateTime expiryTime, CancellationToken cancellationToken = default)
    {
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = expiryTime;
        await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeRefreshTokenAsync(User user, CancellationToken cancellationToken = default)
    {
        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = null;
        await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task UpdateLastLoginAsync(User user, CancellationToken cancellationToken = default)
    {
        user.LastLoginAt = DateTime.UtcNow;
        await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task<UserResponse> UpdateRolesAsync(Guid userId, string[] roles, CancellationToken cancellationToken = default)
    {
        var user = await _unitOfWork.Users.GetByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            return new UserResponse(false, "User not found", null);
        }

        user.Roles = roles;
        await _unitOfWork.Users.UpdateAsync(user, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return new UserResponse(true, "Roles updated successfully", new UserDto(user.Id, user.Username, user.Email, user.Roles));
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await _unitOfWork.Users.GetByIdAsync(id, cancellationToken);
        if (user == null)
        {
            return false;
        }

        await _unitOfWork.Users.DeleteAsync(id, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return true;
    }
}
