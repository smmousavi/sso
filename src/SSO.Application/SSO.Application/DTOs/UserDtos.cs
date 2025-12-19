namespace SSO.Application.DTOs;

public record UserDto(
    Guid Id,
    string Username,
    string Email,
    string[] Roles
);

public record RegisterUserRequest(
    string Username,
    string Email,
    string Password
);

public record UpdateUserRolesRequest(
    string[] Roles
);

public record UserResponse(
    bool Success,
    string? Message,
    UserDto? User
);
