using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthGuard.Infrastructure.DependencyInjection
{
    public static class SharedServiceContainer
    {
        public static IServiceCollection AddSharedService(this IServiceCollection services, IConfiguration config)
        {
            // Add JWT authenction Scheme
            JWTAuthenticationScheme.AddJWTAuthenticationScheme(services, config);
            return services;
        }
    }
}
