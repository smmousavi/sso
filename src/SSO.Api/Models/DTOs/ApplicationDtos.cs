using System.ComponentModel.DataAnnotations;

namespace sso.api.Models.DTOs;

public class RegisterApplicationRequest
{
    [Required]
    public string Name { get; set; } = string.Empty;

    public string[]? AllowedScopes { get; set; }

    public string[]? RedirectUris { get; set; }
}
    
public class ApplicationResponse
{
    public bool Success { get; set; }
    public string? Message { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Name { get; set; }
    public string[]? AllowedScopes { get; set; }
    public string[]? RedirectUris { get; set; }
}
