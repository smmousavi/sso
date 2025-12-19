using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using sso.api.Models.DTOs;
using sso.api.Services;

namespace sso.api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost("register")]
    public async Task<ActionResult<UserResponse>> Register([FromBody] RegisterRequest request)
    {
        var existingUser = await _userService.GetByUsernameAsync(request.Username);
        if (existingUser != null)
        {
            return BadRequest(new UserResponse
            {
                Success = false,
                Message = "Username already exists"
            });
        }

        var existingEmail = await _userService.GetByEmailAsync(request.Email);
        if (existingEmail != null)
        {
            return BadRequest(new UserResponse
            {
                Success = false,
                Message = "Email already exists"
            });
        }

        var user = await _userService.CreateAsync(request.Username, request.Email, request.Password);

        return Ok(new UserResponse
        {
            Success = true,
            Message = "User registered successfully",
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    [Authorize]
    [HttpGet("{id:guid}")]
    public async Task<ActionResult<UserResponse>> GetById(Guid id)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound(new UserResponse
            {
                Success = false,
                Message = "User not found"
            });
        }

        return Ok(new UserResponse
        {
            Success = true,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpGet]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetAll()
    {
        var users = await _userService.GetAllAsync();

        return Ok(users.Select(u => new UserDto
        {
            Id = u.Id,
            Username = u.Username,
            Email = u.Email,
            Roles = u.Roles
        }));
    }

    [Authorize(Roles = "Admin")]
    [HttpPut("{id:guid}/roles")]
    public async Task<ActionResult<UserResponse>> UpdateRoles(Guid id, [FromBody] UpdateRolesRequest request)
    {
        var user = await _userService.GetByIdAsync(id);
        if (user == null)
        {
            return NotFound(new UserResponse
            {
                Success = false,
                Message = "User not found"
            });
        }

        await _userService.UpdateRolesAsync(user, request.Roles);

        return Ok(new UserResponse
        {
            Success = true,
            Message = "Roles updated successfully",
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpDelete("{id:guid}")]
    public async Task<ActionResult<UserResponse>> Delete(Guid id)
    {
        var result = await _userService.DeleteAsync(id);
        if (!result)
        {
            return NotFound(new UserResponse
            {
                Success = false,
                Message = "User not found"
            });
        }

        return Ok(new UserResponse
        {
            Success = true,
            Message = "User deleted successfully"
        });
    }
}
