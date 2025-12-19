namespace SSO.Application.Interfaces;

public interface IUnitOfWork
{
    IUserRepository Users { get; }
    IClientApplicationRepository ClientApplications { get; }
    ISessionRepository Sessions { get; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
