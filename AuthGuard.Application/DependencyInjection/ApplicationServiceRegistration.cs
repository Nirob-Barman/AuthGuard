
using AuthGuard.Application.Services;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGuard.Application.DependencyInjection
{
    public static class ApplicationServiceRegistration
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(ApplicationServiceRegistration).Assembly));
            services.AddScoped<IAuthService, AuthService>();
            return services;
        }
    }
}
