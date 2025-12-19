namespace SSO.Application.DTOs;

public record RegisterApplicationRequest(
    string Name,
    string[]? AllowedScopes,
    string[]? RedirectUris
);

public record ApplicationDto(
    string ClientId,
    string Name,
    string[] AllowedScopes,
    string[] RedirectUris,
    bool IsActive
);

public record ApplicationResponse(
    bool Success,
    string? Message,
    string? ClientId = null,
    string? ClientSecret = null,
    string? Name = null,
    string[]? AllowedScopes = null,
    string[]? RedirectUris = null
);
