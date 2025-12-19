using Microsoft.EntityFrameworkCore;
using SSO.Application.Interfaces;
using SSO.Domain.Entities;

namespace SSO.Infrastructure.Persistence.Repositories;

public class ClientApplicationRepository : IClientApplicationRepository
{
    private readonly SsoDbContext _context;

    public ClientApplicationRepository(SsoDbContext context)
    {
        _context = context;
    }

    public async Task<ClientApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        return await _context.ClientApplications.FindAsync([id], cancellationToken);
    }

    public async Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
    {
        return await _context.ClientApplications
            .FirstOrDefaultAsync(a => a.ClientId == clientId, cancellationToken);
    }

    public async Task<IEnumerable<ClientApplication>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await _context.ClientApplications.Where(a => a.IsActive).ToListAsync(cancellationToken);
    }

    public async Task<ClientApplication> AddAsync(ClientApplication application, CancellationToken cancellationToken = default)
    {
        await _context.ClientApplications.AddAsync(application, cancellationToken);
        return application;
    }

    public Task UpdateAsync(ClientApplication application, CancellationToken cancellationToken = default)
    {
        _context.ClientApplications.Update(application);
        return Task.CompletedTask;
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var app = await GetByIdAsync(id, cancellationToken);
        if (app != null)
        {
            app.IsActive = false;
            _context.ClientApplications.Update(app);
        }
    }
}
