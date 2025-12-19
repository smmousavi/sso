using System.ComponentModel.DataAnnotations;

namespace sso.api.Models.DTOs;

public class LoginRequest
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    public string? ClientId { get; set; }
}

public class RegisterRequest
{
    [Required]
    [MinLength(3)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;
}

public class RefreshTokenRequest
{
    [Required]
    public string AccessToken { get; set; } = string.Empty;

    [Required]
    public string RefreshToken { get; set; } = string.Empty;

    public string? ClientId { get; set; }
}

public class TokenExchangeRequest
{
    [Required]
    public string SsoToken { get; set; } = string.Empty;

    [Required]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    public string ClientSecret { get; set; } = string.Empty;
}

public class ValidateTokenRequest
{
    [Required]
    public string AccessToken { get; set; } = string.Empty;

    public string? ClientId { get; set; }
}

public class ValidateTokenResponse
{
    public bool IsValid { get; set; }
    public string? Message { get; set; }
    public Guid? UserId { get; set; }
    public string? Username { get; set; }
    public string[]? Roles { get; set; }
    public DateTime? ExpiresAt { get; set; }
}

public class LogoutRequest
{
    public string? ClientId { get; set; }
    public bool GlobalLogout { get; set; } = true;
}

public class AuthResponse
{
    public bool Success { get; set; }
    public string? Message { get; set; }
    public string? SessionId { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public UserDto? User { get; set; }
}

public class UserDto
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string[] Roles { get; set; } = [];
}
