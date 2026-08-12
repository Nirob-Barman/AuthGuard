
namespace AuthGuard.Domain.Entities
{
    public class LoginAudit
    {
        public int Id { get; private set; }
        public string? UserId { get; private set; }
        public DateTime LoginTime { get; private set; }
        public bool Succeeded { get; private set; }
        public DateTime? LogoutTime { get; private set; }
        public string? IpAddress { get; private set; }
        public string? UserAgent { get; private set; }

        private LoginAudit() { }

        public static LoginAudit Record(string? userId, string? ipAddress, string? userAgent, bool succeeded)
        {
            return new LoginAudit
            {
                UserId = userId,
                LoginTime = DateTime.UtcNow,
                Succeeded = succeeded,
                IpAddress = ipAddress,
                UserAgent = userAgent
            };
        }
    }
}
