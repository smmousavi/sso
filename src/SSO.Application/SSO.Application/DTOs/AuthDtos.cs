namespace SSO.Application.DTOs;

public record LoginRequest(
    string Username,
    string Password,
    string? ClientId
);

public record RefreshTokenRequest(
    string AccessToken,
    string RefreshToken,
    string? ClientId
);

public record TokenExchangeRequest(
    string SsoToken,
    string ClientId,
    string ClientSecret
);

public record ValidateTokenRequest(
    string AccessToken,
    string? ClientId
);

public record LogoutRequest(
    string? ClientId,
    bool GlobalLogout = true
);

public record AuthResponse(
    bool Success,
    string? Message,
    string? SessionId = null,
    string? AccessToken = null,
    string? RefreshToken = null,
    DateTime? ExpiresAt = null,
    UserDto? User = null
);

public record ValidateTokenResponse(
    bool IsValid,
    string? Message,
    Guid? UserId = null,
    string? Username = null,
    string[]? Roles = null,
    DateTime? ExpiresAt = null
);
