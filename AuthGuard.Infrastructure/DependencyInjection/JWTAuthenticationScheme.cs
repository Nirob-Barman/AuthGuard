using AuthGuard.Application.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace AuthGuard.Infrastructure.DependencyInjection
{
    public static class JWTAuthenticationScheme
    {
        public static IServiceCollection AddJWTAuthenticationScheme(this IServiceCollection services, IConfiguration config) {
            // add JWT service
            
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                var key = Encoding.UTF8.GetBytes(config["JwtSettings:Key"]!);
                var issuer = config["JwtSettings:Issuer"]!;
                var audience = config["JwtSettings:Audience"]!;

                options.RequireHttpsMetadata = false;
                options.SaveToken = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };

                options.Events = new JwtBearerEvents
                {
                    //OnTokenValidated = async context =>
                    //{
                    //    // Get user id from token claims (adjust claim type as per your token)
                    //    var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    //    if (string.IsNullOrEmpty(userId))
                    //    {
                    //        context.Fail("User ID claim is missing.");
                    //        return;
                    //    }

                    //    // Resolve your user service from DI container
                    //    var userService = context.HttpContext.RequestServices.GetRequiredService<IUserManager>();

                    //    var user = await userService.FindByIdAsync(userId);
                    //    if (user == null)
                    //    {
                    //        context.Fail("User not found.");
                    //        return;
                    //    }

                    //    if (user.Id == "48d6375f-91d0-4243-854d-e77519d14ac8")
                    //    {
                    //        context.Fail("User is not active.");
                    //        return;
                    //    }
                    //},


                    // 1. Handles missing or invalid tokens (triggered before controller)
                    OnChallenge = context =>
                    {
                        if (!context.Response.HasStarted)
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                            context.Response.ContentType = "application/json";

                            var errorDescription = context.ErrorDescription ?? "Authentication failed or token is missing.";

                            var result = System.Text.Json.JsonSerializer.Serialize(new
                            {
                                statusCode = 401,
                                message = "Unauthorized. Please provide a valid token.",
                                success = false,
                                data = (object)null!,
                                //errors = new[] { "Authentication failed or token is missing." }
                                errors = new[] { errorDescription }
                            });

                            return context.Response.WriteAsync(result);
                        }

                        return Task.CompletedTask;
                    },

                    // 2. Handles other JWT failures (e.g., token is malformed or invalid)

                    OnAuthenticationFailed = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.ContentType = "application/json";

                        var result = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            statusCode = 401,
                            message = "Token validation failed.",
                            success = false,
                            data = (object)null!,
                            errors = new[] { context.Exception.Message }
                        });

                        return context.Response.WriteAsync(result);
                    },

                    OnForbidden = context =>
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        context.Response.ContentType = "application/json";

                        var result = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            statusCode = 403,
                            message = "Forbidden. You do not have permission to access this resource.",
                            success = false,
                            data = (object)null!,
                            errors = new[] { "Insufficient role or permission." }
                        });

                        return context.Response.WriteAsync(result);
                    }
                };
            });

            return services;
        }
    }
}
