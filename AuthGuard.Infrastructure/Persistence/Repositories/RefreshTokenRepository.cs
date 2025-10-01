using AuthGuard.Application.Interfaces;
using AuthGuard.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthGuard.Infrastructure.Persistence.Repositories
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _context;

        public RefreshTokenRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task AddAsync(RefreshToken token)
        {
            await _context.RefreshTokens.AddAsync(token);
            // SaveChanges is handled by UnitOfWork
        }

        public async Task<RefreshToken?> GetByTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == token);
        }

        public async Task RevokeAsync(string token)
        {
            var existingToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
            if (existingToken != null)
            {
                existingToken.ExpiresAt = DateTime.UtcNow;
            }
        }

        public async Task UpdateAsync(RefreshToken entity)
        {
            _context.RefreshTokens.Update(entity);
        }
    }
}
