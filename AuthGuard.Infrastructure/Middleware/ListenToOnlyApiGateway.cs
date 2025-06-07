using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace AuthGuard.Infrastructure.Middleware
{
    public class ListenToOnlyApiGateway(RequestDelegate next)
    {
        public async Task InvokeAsync(HttpContext context)
        {
            // Extract specific header from the request
            var signedHeader = context.Request.Headers["Api-Gateway"];

            // Allow Swagger UI and documentation endpoints through
            if (context.Request.Path.StartsWithSegments("/swagger"))
            {
                //await next(context); // Pass to next middleware

                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("Sorry, service is unavailable");
                return;
            }

            // Example: Postman
            // Null means, the request is not coming from the Api Gateway // 503 Service unavailable
            if (signedHeader.FirstOrDefault() is null)
            {
                //context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                //await context.Response.WriteAsync("Sorry, service is unavailable");

                var problemDetails = new ProblemDetails
                {
                    Status = StatusCodes.Status503ServiceUnavailable,
                    Title = "Service Unavailable",
                    Detail = "Access is restricted. This service can only be accessed through the API Gateway."
                };

                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.ContentType = "application/problem+json";

                var json = JsonSerializer.Serialize(problemDetails);
                await context.Response.WriteAsync(json);
                return;
            }
            else
            {
                await next(context);
            }

        }
    }
}
