using Microsoft.EntityFrameworkCore;
using SSO.Domain.Entities;

namespace SSO.Infrastructure.Persistence;

public class SsoDbContext : DbContext
{
    public SsoDbContext(DbContextOptions<SsoDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<ClientApplication> ClientApplications => Set<ClientApplication>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<ApplicationToken> ApplicationTokens => Set<ApplicationToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(256);
            entity.Property(e => e.PasswordHash).IsRequired();
            entity.Property(e => e.Roles).HasConversion(
                v => string.Join(',', v),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries));
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
        });

        modelBuilder.Entity<ClientApplication>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.ClientId).IsRequired().HasMaxLength(100);
            entity.Property(e => e.ClientSecretHash).IsRequired();
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.AllowedScopes).HasConversion(
                v => string.Join(',', v),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries));
            entity.Property(e => e.RedirectUris).HasConversion(
                v => string.Join(',', v),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries));
            entity.HasIndex(e => e.ClientId).IsUnique();
        });

        modelBuilder.Entity<UserSession>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.SessionId).IsRequired().HasMaxLength(100);
            entity.HasIndex(e => e.SessionId).IsUnique();
            entity.HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasMany(e => e.ApplicationTokens)
                .WithOne(e => e.UserSession)
                .HasForeignKey(e => e.UserSessionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ApplicationToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.ClientId).IsRequired().HasMaxLength(100);
            entity.Property(e => e.AccessToken).IsRequired();
            entity.Property(e => e.RefreshToken).IsRequired();
            entity.HasIndex(e => new { e.UserSessionId, e.ClientId });
        });
    }
}
