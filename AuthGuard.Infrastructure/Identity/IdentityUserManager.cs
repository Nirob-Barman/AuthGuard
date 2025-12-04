using AuthGuard.Application.Interfaces;
using AuthGuard.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthGuard.Infrastructure.Identity
{
    public class IdentityUserManager : IUserManager
    {
        private readonly UserManager<IdentityUser> _userManager;

        public IdentityUserManager(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<(bool Succeeded, string? UserId, List<string> Errors)> CreateAsync(ApplicationUser user, string password)
        {
            var identityUser = new IdentityUser
            {
                Email = user.Email,
                UserName = user.Email,
            };

            var result = await _userManager.CreateAsync(identityUser, password);
            //return (result.Succeeded, result.Errors.Select(e => e.Description).ToArray());
            if (result.Succeeded)
            {
                return (true, identityUser.Id, new List<string>());
            }
            else
            {
                return (false, null, result.Errors.Select(e => e.Description).ToList());
            }
        }

        public async Task<ApplicationUser?> FindByEmailAsync(string email)
        {
            var identityUser = await _userManager.FindByEmailAsync(email);
            if (identityUser == null) return null;

            return new ApplicationUser
            {
                Id = identityUser.Id,
                Email = identityUser.Email!,
            };
        }

        public async Task<ApplicationUser?> FindByIdAsync(string id)
        {
            var identityUser = await _userManager.FindByIdAsync(id.ToString());
            if (identityUser == null) return null;

            return new ApplicationUser
            {
                Id = identityUser.Id,
                Email = identityUser.Email!,
            };
        }

        public async Task<string[]> GetRolesAsync(ApplicationUser user)
        {
            var identityUser = await _userManager.FindByIdAsync(user.Id!.ToString());
            if (identityUser == null) return Array.Empty<string>();

            var roles = await _userManager.GetRolesAsync(identityUser);
            return roles.ToArray();
        }

        public async Task<bool> CheckPasswordAsync(ApplicationUser user, string password)
        {
            var identityUser = await _userManager.FindByIdAsync(user.Id!.ToString());
            if (identityUser == null) return false;

            return await _userManager.CheckPasswordAsync(identityUser, password);
        }

        public async Task<string> GeneratePasswordResetTokenAsync(ApplicationUser user)
        {
            var identityUser = await _userManager.FindByIdAsync(user.Id!);
            if (identityUser == null)
                return string.Empty;

            return await _userManager.GeneratePasswordResetTokenAsync(identityUser);
        }

        public async Task<(bool Succeeded, List<string> Errors)> ResetPasswordAsync(ApplicationUser user, string token, string newPassword)
        {
            var identityUser = await _userManager.FindByIdAsync(user.Id!);
            if (identityUser == null)
                return (false, new List<string> { "User not found." });

            var result = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);

            return (result.Succeeded, result.Errors.Select(e => e.Description).ToList());
        }


        public async Task<(bool Succeeded, List<string> Errors)> AddToRoleAsync(ApplicationUser user, string roleName)
        {
            //var identityUser = await _userManager.FindByIdAsync(user.Id!);
            var identityUser = await _userManager.FindByEmailAsync(user.Email!);
            if (identityUser == null)
                return (false, new List<string> { "User not found." });

            var result = await _userManager.AddToRoleAsync(identityUser, roleName);
            return (result.Succeeded, result.Errors.Select(e => e.Description).ToList());
        }

        public async Task<(bool Succeeded, List<string> Errors)> RemoveFromRoleAsync(ApplicationUser user, string roleName)
        {
            var identityUser = await _userManager.FindByIdAsync(user.Id!);
            if (identityUser == null)
                return (false, new List<string> { "User not found." });

            var result = await _userManager.RemoveFromRoleAsync(identityUser, roleName);
            return (result.Succeeded, result.Errors.Select(e => e.Description).ToList());
        }

    }
}
