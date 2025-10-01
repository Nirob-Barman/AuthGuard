using AuthGuard.Application.Interfaces;
using AuthGuard.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthGuard.Infrastructure.Identity
{
    public class IdentitySignInManager : ISignInManager
    {
        private readonly SignInManager<IdentityUser> _signInManager;

        public IdentitySignInManager(SignInManager<IdentityUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public async Task<bool> CheckPasswordSignInAsync(ApplicationUser user, string password)
        {
            var identityUser = await _signInManager.UserManager.FindByIdAsync(user.Id!.ToString());
            if (identityUser == null) return false;

            var result = await _signInManager.CheckPasswordSignInAsync(identityUser, password, false);
            return result.Succeeded;
        }
    }
}
