namespace sso.api.Models;

public class ClientApplication
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string[] AllowedScopes { get; set; } = [];
    public string[] RedirectUris { get; set; } = [];
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
}
