using System.Security.Cryptography;
using sso.api.Models;
using SSO.Application.Interfaces;

namespace sso.api.Services;

public class ApplicationService : IApplicationService
{
    private readonly IUnitOfWork _unitOfWork;

    public ApplicationService(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    public async Task<ClientApplication> RegisterAsync(string name, string[]? scopes, string[]? redirectUris)
    {
        var clientId = GenerateClientId();
        var clientSecret = GenerateClientSecret();

        var app = new SSO.Domain.Entities.ClientApplication
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            ClientSecretHash = HashSecret(clientSecret),
            Name = name,
            AllowedScopes = scopes ?? ["openid", "profile", "email"],
            RedirectUris = redirectUris ?? [],
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        await _unitOfWork.ClientApplications.AddAsync(app);
        await _unitOfWork.SaveChangesAsync();

        // Return with unhashed secret for initial display only
        return new ClientApplication
        {
            ClientId = clientId,
            ClientSecret = clientSecret, // Return plain secret only once
            Name = app.Name,
            AllowedScopes = app.AllowedScopes,
            RedirectUris = app.RedirectUris,
            IsActive = app.IsActive,
            CreatedAt = app.CreatedAt
        };
    }

    public async Task<ClientApplication?> GetByClientIdAsync(string clientId)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId);
        if (app == null || !app.IsActive)
            return null;

        return new ClientApplication
        {
            ClientId = app.ClientId,
            ClientSecret = "***", // Never expose secret
            Name = app.Name,
            AllowedScopes = app.AllowedScopes,
            RedirectUris = app.RedirectUris,
            IsActive = app.IsActive,
            CreatedAt = app.CreatedAt
        };
    }

    public async Task<bool> ValidateClientAsync(string clientId, string clientSecret)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId);
        if (app == null || !app.IsActive)
            return false;

        return VerifySecret(clientSecret, app.ClientSecretHash);
    }

    public async Task<IEnumerable<ClientApplication>> GetAllAsync()
    {
        var apps = await _unitOfWork.ClientApplications.GetAllAsync();
        
        return apps.Select(a => new ClientApplication
        {
            ClientId = a.ClientId,
            ClientSecret = "***", // Never expose secret
            Name = a.Name,
            AllowedScopes = a.AllowedScopes,
            RedirectUris = a.RedirectUris,
            IsActive = a.IsActive,
            CreatedAt = a.CreatedAt
        });
    }

    public async Task<bool> DeactivateAsync(string clientId)
    {
        var app = await _unitOfWork.ClientApplications.GetByClientIdAsync(clientId);
        if (app == null)
            return false;

        app.IsActive = false;
        await _unitOfWork.ClientApplications.UpdateAsync(app);
        await _unitOfWork.SaveChangesAsync();
        return true;
    }

    private static string GenerateClientId()
    {
        return $"client_{Guid.NewGuid():N}"[..24];
    }

    private static string GenerateClientSecret()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private static string HashSecret(string secret)
    {
        var salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, 100000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);

        var hashBytes = new byte[48];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 32);

        return Convert.ToBase64String(hashBytes);
    }

    private static bool VerifySecret(string secret, string storedHash)
    {
        var hashBytes = Convert.FromBase64String(storedHash);

        var salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);

        var pbkdf2 = new Rfc2898DeriveBytes(secret, salt, 100000, HashAlgorithmName.SHA256);
        var hash = pbkdf2.GetBytes(32);

        for (int i = 0; i < 32; i++)
        {
            if (hashBytes[i + 16] != hash[i])
                return false;
        }

        return true;
    }
}
