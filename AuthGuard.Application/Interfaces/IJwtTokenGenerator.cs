using AuthGuard.Domain.Entities;

namespace AuthGuard.Application.Interfaces
{
    public interface IJwtTokenGenerator
    {
        Task<(string Token, DateTime ExpiresAt)> GenerateTokenAsync(ApplicationUser user);
        string GenerateRefreshToken();
    }
}
