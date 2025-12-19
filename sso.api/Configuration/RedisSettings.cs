namespace sso.api.Configuration;

public class RedisSettings
{
    public string ConnectionString { get; set; } = "localhost:6379";
    public string InstanceName { get; set; } = "SSO_";
    public int SessionExpirationHours { get; set; } = 24;
}
