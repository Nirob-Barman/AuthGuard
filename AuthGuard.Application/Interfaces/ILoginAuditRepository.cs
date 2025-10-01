
using AuthGuard.Domain.Entities;

namespace AuthGuard.Application.Interfaces
{
    public interface ILoginAuditRepository
    {
        Task AddAsync(LoginAudit audit);
    }
}
