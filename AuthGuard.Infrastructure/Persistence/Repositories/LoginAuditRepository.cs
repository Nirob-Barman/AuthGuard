using AuthGuard.Application.Interfaces;
using AuthGuard.Domain.Entities;

namespace AuthGuard.Infrastructure.Persistence.Repositories
{
    public class LoginAuditRepository : ILoginAuditRepository
    {
        private readonly ApplicationDbContext _context;

        public LoginAuditRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task AddAsync(LoginAudit audit)
        {
            await _context.LoginAudits.AddAsync(audit);
        }
    }
}
