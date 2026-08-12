
namespace AuthGuard.Domain.Entities
{
    public class RefreshToken
    {
        public string? Token { get; private set; }
        public string? UserId { get; private set; }
        public DateTime ExpiresAt { get; private set; }
        public bool IsRevoked { get; private set; }
        public DateTime CreatedAt { get; private set; }

        private RefreshToken() { }

        public static RefreshToken Issue(string? userId, string token, DateTime expiresAt)
        {
            return new RefreshToken
            {
                Token = token,
                UserId = userId,
                ExpiresAt = expiresAt,
                IsRevoked = false,
                CreatedAt = DateTime.UtcNow
            };
        }

        public bool IsActive => !IsRevoked && ExpiresAt > DateTime.UtcNow;

        public void Revoke()
        {
            IsRevoked = true;
        }
    }
}
