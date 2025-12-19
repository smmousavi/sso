namespace SSO.Domain.Entities;

public class ClientApplication
{
    public Guid Id { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecretHash { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string[] AllowedScopes { get; set; } = [];
    public string[] RedirectUris { get; set; } = [];
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
}
