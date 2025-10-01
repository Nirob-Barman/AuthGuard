using AuthGuard.Domain.Entities;

namespace AuthGuard.Application.Interfaces
{
    public interface IRefreshTokenRepository
    {
        Task AddAsync(RefreshToken token);
        Task<RefreshToken?> GetByTokenAsync(string token);
        Task RevokeAsync(string token);
        Task UpdateAsync(RefreshToken entity);
    }
}
