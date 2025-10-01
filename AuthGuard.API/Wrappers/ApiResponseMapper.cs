using AuthGuard.Application.Wrappers;
using Microsoft.AspNetCore.Mvc;

namespace AuthGuard.API.Wrappers
{
    public class ApiResponseMapper
    {
        public static IActionResult FromResult<T>(ControllerBase controller, Result<T> result)
        {
            if (result.Success)
            {
                //return controller.Ok(ApiResponse<T>.SuccessResponse(result.Data!, result.Message ?? "Success"));
                return result.ResultType switch
                {
                    ResultType.Created => controller.StatusCode(201, ApiResponse<T>.CreatedResponse(result.Data!, result.Message ?? "Resource created")),
                    ResultType.NoContent => controller.NoContent(), // No body on 204
                    _ => controller.Ok(ApiResponse<T>.SuccessResponse(result.Data!, result.Message ?? "Success"))
                };
            }

            return result.ResultType switch
            {
                ResultType.ValidationError => controller.BadRequest(ApiResponse<T>.FailResponse(result.Message ?? "Validation error", result.Errors, 400)),
                ResultType.BadRequest => controller.BadRequest(ApiResponse<T>.FailResponse(result.Message ?? "Bad Request", result.Errors, 400)),
                ResultType.Unauthorized => controller.Unauthorized(ApiResponse<T>.FailResponse(result.Message ?? "Unauthorized", result.Errors, 401)),
                ResultType.Forbidden => controller.StatusCode(403, ApiResponse<T>.FailResponse(result.Message ?? "Forbidden", result.Errors, 403)),
                //ResultType.Forbidden => controller.Forbid(),
                //ResultType.Forbidden => controller.Forbid(ApiResponse<T>.FailResponse(result.Message ?? "Forbidden", result.Errors, 403)),
                ResultType.NotFound => controller.NotFound(ApiResponse<T>.FailResponse(result.Message ?? "Not found", result.Errors, 404)),
                ResultType.Conflict => controller.Conflict(ApiResponse<T>.FailResponse(result.Message ?? "Conflict", result.Errors, 409)),
                ResultType.ValidationFailed => controller.UnprocessableEntity(ApiResponse<T>.FailResponse(result.Message ?? "Validation Failed", result.Errors, 422)),
                ResultType.TooManyRequests => controller.StatusCode(429, ApiResponse<T>.FailResponse(result.Message ?? "Too Many Requests", result.Errors, 429)),
                ResultType.ServiceUnavailable => controller.StatusCode(503, ApiResponse<T>.FailResponse(result.Message ?? "Service Unavailable", result.Errors, 503)),
                ResultType.Failure => controller.StatusCode(500, ApiResponse<T>.FailResponse(result.Message ?? "Internal Server Error", result.Errors, 500)),
                _ => controller.StatusCode(500, ApiResponse<T>.FailResponse(result.Message ?? "Unknown error occurred", result.Errors, 500))
            };
        }
    }
}
