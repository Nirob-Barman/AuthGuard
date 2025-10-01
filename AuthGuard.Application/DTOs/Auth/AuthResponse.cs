
namespace AuthGuard.Application.DTOs.Auth
{
    public class AuthResponse
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime ExpiresAt { get; set; }
        public string? Email { get; set; }
        public string? Role { get; set; }
    }
}
