namespace AuthGuard.Application.Wrappers
{
    public class Result<T>
    {
        public bool Success { get; set; }
        public string? Message { get; set; }
        public T? Data { get; set; }
        public List<string>? Errors { get; set; }
        public ResultType ResultType { get; set; }


        // Success
        public static Result<T> Ok(T? data, string? message = null, ResultType resultType = ResultType.Success)
        {
            return new Result<T>
            {
                Success = true,
                Data = data,
                Message = message,
                ResultType = resultType
            };
        }

        // Failure - single error
        public static Result<T> Fail(string error, string? message = null, ResultType resultType = ResultType.Failure)
        {
            return new Result<T>
            {
                Success = false,
                Errors = new List<string> { error },
                Message = message,
                ResultType = resultType
            };
        }

        // Failure - multiple errors
        public static Result<T> Fail(List<string> errors, string? message = null, ResultType resultType = ResultType.Failure)
        {
            return new Result<T>
            {
                Success = false,
                Errors = errors,
                Message = message,
                ResultType = resultType
            };
        }

        // Manual creation
        public static Result<T> From(bool success, T? data = default, string? message = null, List<string>? errors = null, ResultType resultType = ResultType.Success)
        {
            return new Result<T>
            {
                Success = success,
                Data = data,
                Message = message,
                Errors = errors,
                ResultType = resultType
            };
        }
    }

    public enum ResultType
    {
        Success,
        ValidationError,
        Unauthorized,
        Forbidden,
        NotFound,
        Conflict,
        Failure,
        Created,
        NoContent,
        ValidationFailed,
        TooManyRequests,
        BadRequest,
        ServiceUnavailable
    }
}
