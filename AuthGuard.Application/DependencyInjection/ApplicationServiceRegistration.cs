
using AuthGuard.Application.Services;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGuard.Application.DependencyInjection
{
    public static class ApplicationServiceRegistration
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddScoped<IAuthService, AuthService>();
            return services;
        }
    }
}
