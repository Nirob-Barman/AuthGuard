using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Interfaces.Email;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class RequestPasswordResetCommandHandler : IRequestHandler<RequestPasswordResetCommand, Result<string>>
    {
        private readonly IUserManager _userManager;
        private readonly IEmailService _emailService;

        public RequestPasswordResetCommandHandler(IUserManager userManager, IEmailService emailService)
        {
            _userManager = userManager;
            _emailService = emailService;
        }

        public async Task<Result<string>> Handle(RequestPasswordResetCommand command, CancellationToken cancellationToken)
        {
            var validationErrors = IdentityRequestValidator.ValidatePasswordResetRequestEmail(command.Email);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var user = await _userManager.FindByEmailAsync(command.Email);
            if (user == null)
                throw new KeyNotFoundException("User with the specified email does not exist.");

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            if (string.IsNullOrEmpty(resetToken))
                throw new UnauthorizedAccessException("Failed to generate password reset token.");

            var resetLink = $"https://yourfrontend/reset-password?email={Uri.EscapeDataString(command.Email)}&token={Uri.EscapeDataString(resetToken)}";
            var emailBody = $"Click the link below to reset your password:<br><a href='{resetLink}'>Reset Password</a>";

            await _emailService.SendEmailAsync(command.Email, "Password Reset Request", emailBody);

            return Result<string>.Ok("Password reset email sent.", "Request succeeded");
        }
    }
}
