using SSO.Domain.Entities;

namespace SSO.Application.Interfaces;

public interface IClientApplicationRepository
{
    Task<ClientApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<ClientApplication?> GetByClientIdAsync(string clientId, CancellationToken cancellationToken = default);
    Task<IEnumerable<ClientApplication>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<ClientApplication> AddAsync(ClientApplication application, CancellationToken cancellationToken = default);
    Task UpdateAsync(ClientApplication application, CancellationToken cancellationToken = default);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);
}
