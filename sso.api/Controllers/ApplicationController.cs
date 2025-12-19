using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using sso.api.Models.DTOs;
using sso.api.Services;

namespace sso.api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ApplicationController : ControllerBase
{
    private readonly IApplicationService _applicationService;

    public ApplicationController(IApplicationService applicationService)
    {
        _applicationService = applicationService;
    }

    [HttpPost("register")]
    //[Authorize(Roles = "Admin")]
    public async Task<ActionResult<ApplicationResponse>> Register([FromBody] RegisterApplicationRequest request)
    {
        var app = await _applicationService.RegisterAsync(request.Name, request.AllowedScopes, request.RedirectUris);

        return Ok(new ApplicationResponse
        {
            Success = true,
            Message = "Application registered successfully. Store the client secret securely - it won't be shown again.",
            ClientId = app.ClientId,
            ClientSecret = app.ClientSecret,
            Name = app.Name,
            AllowedScopes = app.AllowedScopes,
            RedirectUris = app.RedirectUris
        });
    }

    [HttpGet]
    //[Authorize(Roles = "Admin")]
    public async Task<ActionResult<IEnumerable<ApplicationResponse>>> GetAll()
    {
        var apps = await _applicationService.GetAllAsync();

        return Ok(apps.Select(a => new ApplicationResponse
        {
            Success = true,
            ClientId = a.ClientId,
            Name = a.Name,
            AllowedScopes = a.AllowedScopes,
            RedirectUris = a.RedirectUris
        }));
    }

    [HttpDelete("{clientId}")]
    //[Authorize(Roles = "Admin")]
    public async Task<ActionResult<ApplicationResponse>> Deactivate(string clientId)
    {
        var result = await _applicationService.DeactivateAsync(clientId);

        if (!result)
        {
            return NotFound(new ApplicationResponse
            {
                Success = false,
                Message = "Application not found"
            });
        }

        return Ok(new ApplicationResponse
        {
            Success = true,
            Message = "Application deactivated successfully"
        });
    }
}
