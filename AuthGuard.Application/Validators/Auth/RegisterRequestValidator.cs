using AuthGuard.Application.DTOs.Auth;

namespace AuthGuard.Application.Validators.Auth
{
    public static class RegisterRequestValidator
    {
        //public static string[] Validate(RegisterRequest request)
        public static List<string> Validate(RegisterRequest request)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(request.Email))
                errors.Add("Email is required.");

            if (string.IsNullOrWhiteSpace(request.Password))
                errors.Add("Password is required.");

            //if (string.IsNullOrWhiteSpace(request.FullName))
            //    errors.Add("Full name is required.");

            if (string.IsNullOrWhiteSpace(request.Role))
                errors.Add("Role is required.");

            //return errors.ToArray();
            return errors;
        }
    }
}
