
using AuthGuard.Application.Behaviors;
using AuthGuard.Application.Services;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGuard.Application.DependencyInjection
{
    public static class ApplicationServiceRegistration
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services)
        {
            services.AddMediatR(cfg =>
            {
                cfg.RegisterServicesFromAssembly(typeof(ApplicationServiceRegistration).Assembly);
                cfg.AddOpenBehavior(typeof(TransactionBehavior<,>));
            });
            services.AddScoped<IAuthService, AuthService>();
            return services;
        }
    }
}
