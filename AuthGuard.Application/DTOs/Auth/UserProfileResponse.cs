
namespace AuthGuard.Application.DTOs.Auth
{
    public class UserProfileResponse
    {
        public string? Id { get; set; }
        public string? Email { get; set; }
        public List<string>? Roles { get; set; }
    }
}
