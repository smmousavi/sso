namespace SSO.Domain.Entities;

public class UserSession
{
    public Guid Id { get; set; }
    public string SessionId { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    public ICollection<ApplicationToken> ApplicationTokens { get; set; } = [];
}
