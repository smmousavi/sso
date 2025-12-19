using SSO.Application.DTOs;
using SSO.Application.Interfaces;
using SSO.Domain.Entities;

namespace SSO.Application.Services;

public class ClientApplicationService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher _passwordHasher;

    public ClientApplicationService(IUnitOfWork unitOfWork, IPasswordHasher passwordHasher)
    {
        _unitOfWork = unitOfWork;
        _passwordHasher = passwordHasher;
    }

    public async Task<ApplicationResponse> RegisterAsync(RegisterApplicationRequest request, CancellationToken cancellationToken = default)
    {
        var clientId = GenerateClientId();
        var clientSecret = GenerateClientSecret();

        var app = new ClientApplication
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            ClientSecretHash = _passwordHasher.HashPassword(clientSecret),
            Name = request.Name,
            AllowedScopes = request.AllowedScopes ?? ["openid", "profile", "email"],
            RedirectUris = request.RedirectUris ?? [],
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        await _unitOfWork.ClientApplications.AddAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return new ApplicationResponse(
            true,
            "Application registered successfully. Store the client secret securely - it won't be shown again.",
            clientId,
            clientSecret,
            app.Name,
            app.AllowedScopes,
            app.RedirectUris
        );
    }

    public async Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId, cancellationToken);
        return app?.IsActive == true ? app : null;
    }

    public async Task<bool> ValidateClientAsync(string clientId, string clientSecret, CancellationToken cancellationToken = default)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId, cancellationToken);
        if (app == null || !app.IsActive)
            return false;

        return _passwordHasher.VerifyPassword(clientSecret, app.ClientSecretHash);
    }

    public async Task<IEnumerable<ApplicationDto>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var apps = await _unitOfWork.ClientApplications.GetAllAsync(cancellationToken);
        return apps.Where(a => a.IsActive).Select(a => new ApplicationDto(
            a.ClientId,
            a.Name,
            a.AllowedScopes,
            a.RedirectUris,
            a.IsActive
        ));
    }

    public async Task<bool> DeactivateAsync(string clientId, CancellationToken cancellationToken = default)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId, cancellationToken);
        if (app == null)
            return false;

        app.IsActive = false;
        await _unitOfWork.ClientApplications.UpdateAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return true;
    }

    private static string GenerateClientId()
    {
        return $"client_{Guid.NewGuid():N}"[..24];
    }

    private static string GenerateClientSecret()
    {
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
