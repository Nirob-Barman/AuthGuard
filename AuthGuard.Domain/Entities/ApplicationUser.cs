
namespace AuthGuard.Domain.Entities
{
    public class ApplicationUser
    {
        public string? Id { get; private set; }
        public string? Email { get; private set; }

        private ApplicationUser() { }

        public static ApplicationUser Create(string? email)
        {
            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentException("Email is required.");

            return new ApplicationUser { Email = email };
        }

        public static ApplicationUser Existing(string? id, string? email)
        {
            return new ApplicationUser { Id = id, Email = email };
        }
    }
}
