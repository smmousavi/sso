using System.Collections.Concurrent;
using System.Security.Cryptography;
using sso.api.Models;

namespace sso.api.Services;

public class ApplicationService : IApplicationService
{
    private static readonly ConcurrentDictionary<string, ClientApplication> _applications = new();

    public Task<ClientApplication> RegisterAsync(string name, string[]? scopes, string[]? redirectUris)
    {
        var clientId = GenerateClientId();
        var clientSecret = GenerateClientSecret();

        var app = new ClientApplication
        {
            ClientId = clientId,
            ClientSecret = HashSecret(clientSecret),
            Name = name,
            AllowedScopes = scopes ?? ["openid", "profile", "email"],
            RedirectUris = redirectUris ?? [],
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        _applications.TryAdd(clientId, app);

        // Return with unhashed secret for initial display only
        return Task.FromResult(new ClientApplication
        {
            ClientId = clientId,
            ClientSecret = clientSecret, // Return plain secret only once
            Name = app.Name,
            AllowedScopes = app.AllowedScopes,
            RedirectUris = app.RedirectUris,
            IsActive = app.IsActive,
            CreatedAt = app.CreatedAt
        });
    }

    public Task<ClientApplication?> GetByClientIdAsync(string clientId)
    {
        _applications.TryGetValue(clientId, out var app);
        if (app == null || !app.IsActive)
            return Task.FromResult<ClientApplication?>(null);

        return Task.FromResult<ClientApplication?>(app);
    }

    public Task<bool> ValidateClientAsync(string clientId, string clientSecret)
    {
        if (!_applications.TryGetValue(clientId, out var app))
            return Task.FromResult(false);

        if (!app.IsActive)
            return Task.FromResult(false);

        return Task.FromResult(VerifySecret(clientSecret, app.ClientSecret));
    }

    public Task<IEnumerable<ClientApplication>> GetAllAsync()
    {
        var apps = _applications.Values
            .Where(a => a.IsActive)
            .Select(a => new ClientApplication
            {
                ClientId = a.ClientId,
                ClientSecret = "***", // Never expose secret
                Name = a.Name,
                AllowedScopes = a.AllowedScopes,
                RedirectUris = a.RedirectUris,
                IsActive = a.IsActive,
                CreatedAt = a.CreatedAt
            });

        return Task.FromResult(apps);
    }

    public Task<bool> DeactivateAsync(string clientId)
    {
        if (!_applications.TryGetValue(clientId, out var app))
            return Task.FromResult(false);

        app.IsActive = false;
        return Task.FromResult(true);
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
