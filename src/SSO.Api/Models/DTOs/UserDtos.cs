using System.ComponentModel.DataAnnotations;

namespace sso.api.Models.DTOs;

public class UserResponse
{
    public bool Success { get; set; }
    public string? Message { get; set; }
    public UserDto? User { get; set; }
}

public class UpdateRolesRequest
{
    [Required]
    public string[] Roles { get; set; } = [];
}
