
using Microsoft.AspNetCore.Builder;

namespace AuthGuard.Infrastructure.Middleware
{
    public static class MiddlewareExtensions
    {
        public static IApplicationBuilder UseCustomMiddlewares(this IApplicationBuilder app)
        {
            app.UseMiddleware<ExceptionMiddleware>();
            //app.UseMiddleware<ListenToOnlyApiGateway>();

            return app;
        }
    }
}
