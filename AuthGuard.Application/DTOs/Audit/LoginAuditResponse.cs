namespace AuthGuard.Application.DTOs.Audit
{
    public class LoginAuditResponse
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public DateTime LoginTime { get; set; }
        public bool Succeeded { get; set; }
        public DateTime? LogoutTime { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
    }
}
