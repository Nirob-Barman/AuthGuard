using AuthGuard.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthGuard.Application.Interfaces
{
    public interface ISignInManager
    {
        Task<bool> CheckPasswordSignInAsync(ApplicationUser user, string password);
    }
}
