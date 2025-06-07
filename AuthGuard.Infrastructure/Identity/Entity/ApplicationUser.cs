
using Microsoft.AspNetCore.Identity;

namespace AuthGuard.Infrastructure.Identity.Entity
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
