using AuthGuard.Domain.Entities;

namespace AuthGuard.Application.Interfaces
{
    public interface IUserManager
    {
        Task<(bool Succeeded, string? UserId, List<string> Errors)> CreateAsync(ApplicationUser user, string password);
        Task<ApplicationUser?> FindByEmailAsync(string email);
        Task<ApplicationUser?> FindByIdAsync(string id);
        Task<string[]> GetRolesAsync(ApplicationUser user);
        Task<bool> CheckPasswordAsync(ApplicationUser user, string password);
        Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user);
        Task<(bool Succeeded, List<string> Errors)> ResetPasswordAsync(ApplicationUser user, string token, string newPassword);
        //Task<bool> IsInRoleAsync(ApplicationUser user, string role);
        Task<(bool Succeeded, List<string> Errors)> AddToRoleAsync(ApplicationUser user, string roleName);
        Task<(bool Succeeded, List<string> Errors)> RemoveFromRoleAsync(ApplicationUser user, string roleName);

    }
}
