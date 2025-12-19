namespace SSO.Domain.Entities;

public class ApplicationToken
{
    public Guid Id { get; set; }
    public Guid UserSessionId { get; set; }
    public UserSession UserSession { get; set; } = null!;
    public string ClientId { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime AccessTokenExpiresAt { get; set; }
    public DateTime RefreshTokenExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime CreatedAt { get; set; }
}
