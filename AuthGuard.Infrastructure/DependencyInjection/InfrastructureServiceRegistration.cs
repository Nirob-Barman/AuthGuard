using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Interfaces.Email;
using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Services;
using AuthGuard.Application.Settings;
using AuthGuard.Application.Settings.Email;
using AuthGuard.Infrastructure.Identity;
using AuthGuard.Infrastructure.Persistence;
using AuthGuard.Infrastructure.Persistence.Repositories;
using AuthGuard.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGuard.Infrastructure.DependencyInjection
{
    public static class InfrastructureServiceRegistration
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
        {
            services.Configure<JwtSettings>(config.GetSection("JwtSettings"));

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(config.GetConnectionString("DefaultConnection")));

            services.AddIdentityCore<IdentityUser>(options =>
            {
                // Identity options here
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequiredLength = 6;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

            //services.AddScoped<IJwtTokenService, JwtTokenService>();
            services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

            services.AddScoped<IAuthService, AuthService>();
            //services.AddScoped<IIdentityService, IdentityService>();
            services.AddScoped<IUserManager, IdentityUserManager>();
            services.AddScoped<IRoleManager, RoleManager>();
            services.AddScoped<ISignInManager, IdentitySignInManager>();

            //services.AddScoped<ILoginAuditRepository, LoginAuditRepository>();
            //services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();

            services.Configure<EmailSettings>(config.GetSection("EmailSettings"));
            services.AddScoped<IEmailService, EmailService>();

            services.AddScoped<IUnitOfWork, UnitOfWork>();
            services.AddScoped(typeof(IRepository<>), typeof(GenericRepository<>));

            return services;
        }
    }
}
