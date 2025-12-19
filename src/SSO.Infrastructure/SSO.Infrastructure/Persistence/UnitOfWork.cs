using SSO.Application.Interfaces;
using SSO.Infrastructure.Persistence.Repositories;

namespace SSO.Infrastructure.Persistence;

public class UnitOfWork : IUnitOfWork
{
    private readonly SsoDbContext _context;
    private IUserRepository? _users;
    private IClientApplicationRepository? _clientApplications;
    private ISessionRepository? _sessions;

    public UnitOfWork(SsoDbContext context)
    {
        _context = context;
    }

    public IUserRepository Users => _users ??= new UserRepository(_context);

    public IClientApplicationRepository ClientApplications => _clientApplications ??= new ClientApplicationRepository(_context);

    public ISessionRepository Sessions => _sessions ??= new SessionRepository(_context);

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.SaveChangesAsync(cancellationToken);
    }
}
