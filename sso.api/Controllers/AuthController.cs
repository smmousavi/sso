using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using sso.api.Configuration;
using sso.api.Models;
using sso.api.Models.DTOs;
using sso.api.Services;

namespace sso.api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ITokenService _tokenService;
    private readonly ISessionService _sessionService;
    private readonly IApplicationService _applicationService;
    private readonly JwtSettings _jwtSettings;

    public AuthController(
        IUserService userService,
        ITokenService tokenService,
        ISessionService sessionService,
        IApplicationService applicationService,
        IOptions<JwtSettings> jwtSettings)
    {
        _userService = userService;
        _tokenService = tokenService;
        _sessionService = sessionService;
        _applicationService = applicationService;
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.GetByUsernameAsync(request.Username);
        if (user == null)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid username or password"
            });
        }

        var isValidPassword = await _userService.ValidatePasswordAsync(user, request.Password);
        if (!isValidPassword)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid username or password"
            });
        }

        // Check for existing session or create new one
        var session = await _sessionService.GetSessionByUserIdAsync(user.Id);
        if (session == null)
        {
            session = await _sessionService.CreateSessionAsync(user);
        }

        var accessToken = _tokenService.GenerateAccessToken(user, request.ClientId, session.SessionId);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // If client ID provided, store as application token
        if (!string.IsNullOrEmpty(request.ClientId))
        {
            var app = await _applicationService.GetByClientIdAsync(request.ClientId);
            if (app != null)
            {
                var appToken = new ApplicationToken
                {
                    ClientId = request.ClientId,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays)
                };
                await _sessionService.AddApplicationTokenAsync(session.SessionId, appToken);
            }
        }

        await _userService.UpdateRefreshTokenAsync(
            user,
            refreshToken,
            DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays));

        await _userService.UpdateLastLoginAsync(user);

        return Ok(new AuthResponse
        {
            Success = true,
            Message = "Login successful",
            SessionId = session.SessionId,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    /// <summary>
    /// Exchange SSO token for application-specific token
    /// </summary>
    [HttpPost("token/exchange")]
    public async Task<ActionResult<AuthResponse>> ExchangeToken([FromBody] TokenExchangeRequest request)
    {
        // Validate client credentials
        var isValidClient = await _applicationService.ValidateClientAsync(request.ClientId, request.ClientSecret);
        if (!isValidClient)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid client credentials"
            });
        }

        // Validate SSO token
        var principal = _tokenService.ValidateToken(request.SsoToken);
        if (principal == null)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid or expired SSO token"
            });
        }

        // Check if token is revoked
        var isRevoked = await _sessionService.IsTokenRevokedAsync(request.SsoToken);
        if (isRevoked)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Token has been revoked"
            });
        }

        // Get session from token
        var sessionId = _tokenService.GetSessionIdFromToken(request.SsoToken);
        if (string.IsNullOrEmpty(sessionId))
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid session"
            });
        }

        var session = await _sessionService.GetSessionAsync(sessionId);
        if (session == null || session.IsRevoked)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Session expired or revoked"
            });
        }

        // Get user
        var user = await _userService.GetByIdAsync(session.UserId);
        if (user == null)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "User not found"
            });
        }

        // Generate application-specific tokens
        var accessToken = _tokenService.GenerateAccessToken(user, request.ClientId, sessionId);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Store application token in session
        var appToken = new ApplicationToken
        {
            ClientId = request.ClientId,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays)
        };
        await _sessionService.AddApplicationTokenAsync(sessionId, appToken);

        return Ok(new AuthResponse
        {
            Success = true,
            Message = "Token exchanged successfully",
            SessionId = sessionId,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    /// <summary>
    /// Validate a token - returns false if token is expired or revoked
    /// </summary>
    [HttpPost("token/validate")]
    public async Task<ActionResult<ValidateTokenResponse>> ValidateToken([FromBody] ValidateTokenRequest request)
    {
        // First check if token is revoked
        var isRevoked = await _sessionService.IsTokenRevokedAsync(request.AccessToken);
        if (isRevoked)
        {
            return Ok(new ValidateTokenResponse
            {
                IsValid = false,
                Message = "Token has been revoked"
            });
        }

        // Validate token signature and expiration
        var principal = _tokenService.ValidateToken(request.AccessToken);
        if (principal == null)
        {
            return Ok(new ValidateTokenResponse
            {
                IsValid = false,
                Message = "Invalid or expired token"
            });
        }

        // Check session validity
        var sessionId = _tokenService.GetSessionIdFromToken(request.AccessToken);
        if (!string.IsNullOrEmpty(sessionId))
        {
            var session = await _sessionService.GetSessionAsync(sessionId);
            if (session == null || session.IsRevoked)
            {
                return Ok(new ValidateTokenResponse
                {
                    IsValid = false,
                    Message = "Session has been revoked"
                });
            }

            // If client ID provided, check if that specific app token is revoked
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var appToken = await _sessionService.GetApplicationTokenAsync(sessionId, request.ClientId);
                if (appToken == null || appToken.IsRevoked)
                {
                    return Ok(new ValidateTokenResponse
                    {
                        IsValid = false,
                        Message = "Application token has been revoked"
                    });
                }
            }
        }

        // Extract user info from token
        var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        var username = principal.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value;
        var roles = principal.FindAll(System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).ToArray();

        Guid.TryParse(userIdClaim, out var userId);

        return Ok(new ValidateTokenResponse
        {
            IsValid = true,
            Message = "Token is valid",
            UserId = userId,
            Username = username,
            Roles = roles
        });
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        // Check if token is revoked
        var isRevoked = await _sessionService.IsTokenRevokedAsync(request.AccessToken);
        if (isRevoked)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Token has been revoked"
            });
        }

        var principal = _tokenService.GetPrincipalFromExpiredToken(request.AccessToken);
        if (principal == null)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid access token"
            });
        }

        var userIdClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid token claims"
            });
        }

        var user = await _userService.GetByIdAsync(userId);
        if (user == null)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "User not found"
            });
        }

        // Check session
        var sessionId = _tokenService.GetSessionIdFromToken(request.AccessToken);
        if (!string.IsNullOrEmpty(sessionId))
        {
            var session = await _sessionService.GetSessionAsync(sessionId);
            if (session == null || session.IsRevoked)
            {
                return Unauthorized(new AuthResponse
                {
                    Success = false,
                    Message = "Session expired or revoked"
                });
            }

            // If client-specific refresh
            if (!string.IsNullOrEmpty(request.ClientId))
            {
                var appToken = await _sessionService.GetApplicationTokenAsync(sessionId, request.ClientId);
                if (appToken == null || appToken.RefreshToken != request.RefreshToken || appToken.IsRevoked)
                {
                    return Unauthorized(new AuthResponse
                    {
                        Success = false,
                        Message = "Invalid or expired refresh token"
                    });
                }

                // Revoke old token
                await _sessionService.RevokeTokenAsync(request.AccessToken);

                // Generate new tokens
                var newAccessToken = _tokenService.GenerateAccessToken(user, request.ClientId, sessionId);
                var newRefreshToken = _tokenService.GenerateRefreshToken();

                // Update application token
                var newAppToken = new ApplicationToken
                {
                    ClientId = request.ClientId,
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays)
                };
                await _sessionService.AddApplicationTokenAsync(sessionId, newAppToken);

                return Ok(new AuthResponse
                {
                    Success = true,
                    Message = "Token refreshed successfully",
                    SessionId = sessionId,
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                    User = new UserDto
                    {
                        Id = user.Id,
                        Username = user.Username,
                        Email = user.Email,
                        Roles = user.Roles
                    }
                });
            }
        }

        // Standard refresh (non-client specific)
        if (user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return Unauthorized(new AuthResponse
            {
                Success = false,
                Message = "Invalid or expired refresh token"
            });
        }

        // Revoke old token
        await _sessionService.RevokeTokenAsync(request.AccessToken);

        var accessToken = _tokenService.GenerateAccessToken(user, null, sessionId);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _userService.UpdateRefreshTokenAsync(
            user,
            refreshToken,
            DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays));

        return Ok(new AuthResponse
        {
            Success = true,
            Message = "Token refreshed successfully",
            SessionId = sessionId,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Roles = user.Roles
            }
        });
    }

    /// <summary>
    /// Logout - supports single app logout or global SSO logout
    /// </summary>
    [Authorize]
    [HttpPost("logout")]
    public async Task<ActionResult<AuthResponse>> Logout([FromBody] LogoutRequest? request)
    {
        var token = HttpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");

        var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return BadRequest(new AuthResponse
            {
                Success = false,
                Message = "Invalid token"
            });
        }

        var sessionId = _tokenService.GetSessionIdFromToken(token);

        // Global logout (default) - revoke entire session
        if (request?.GlobalLogout != false)
        {
            if (!string.IsNullOrEmpty(sessionId))
            {
                await _sessionService.RevokeSessionAsync(sessionId);
            }

            var user = await _userService.GetByIdAsync(userId);
            if (user != null)
            {
                await _userService.RevokeRefreshTokenAsync(user);
            }

            return Ok(new AuthResponse
            {
                Success = true,
                Message = "Logged out from all applications successfully"
            });
        }

        // Single application logout
        if (!string.IsNullOrEmpty(request?.ClientId) && !string.IsNullOrEmpty(sessionId))
        {
            await _sessionService.RevokeApplicationTokenAsync(sessionId, request.ClientId);

            return Ok(new AuthResponse
            {
                Success = true,
                Message = $"Logged out from application {request.ClientId} successfully"
            });
        }

        // Revoke current token only
        await _sessionService.RevokeTokenAsync(token);

        return Ok(new AuthResponse
        {
            Success = true,
            Message = "Logged out successfully"
        });
    }

    /// <summary>
    /// Get list of applications the user is currently logged into
    /// </summary>
    [Authorize]
    [HttpGet("sessions")]
    public async Task<ActionResult<object>> GetActiveSessions()
    {
        var token = HttpContext.Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        var sessionId = _tokenService.GetSessionIdFromToken(token);

        if (string.IsNullOrEmpty(sessionId))
        {
            return Ok(new { Applications = Array.Empty<string>() });
        }

        var clientIds = await _sessionService.GetActiveSessionClientIdsAsync(sessionId);

        return Ok(new
        {
            SessionId = sessionId,
            Applications = clientIds
        });
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserDto>> GetCurrentUser()
    {
        var userIdClaim = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            return Unauthorized();
        }

        var user = await _userService.GetByIdAsync(userId);
        if (user == null)
        {
            return NotFound();
        }

        return Ok(new UserDto
        {
            Id = user.Id,
            Username = user.Username,
            Email = user.Email,
            Roles = user.Roles
        });
    }
}
