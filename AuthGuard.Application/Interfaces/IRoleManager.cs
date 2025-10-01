
namespace AuthGuard.Application.Interfaces
{
    public interface IRoleManager
    {
        Task<bool> RoleExistsAsync(string roleName);
        Task<(bool Succeeded, List<string> Errors)> CreateRoleAsync(string roleName);
        Task<(bool Succeeded, List<string> Errors)> DeleteRoleAsync(string roleName);
    }
}
