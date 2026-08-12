using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class ResetPasswordCommandHandler : IRequestHandler<ResetPasswordCommand, Result<string>>
    {
        private readonly IUserManager _userManager;

        public ResetPasswordCommandHandler(IUserManager userManager)
        {
            _userManager = userManager;
        }

        public async Task<Result<string>> Handle(ResetPasswordCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateResetPasswordRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var user = await _userManager.FindByEmailAsync(request.Email!);
            if (user == null)
                throw new KeyNotFoundException("User not found.");

            var resetResult = await _userManager.ResetPasswordAsync(user, request.Token!, request.NewPassword!);

            if (!resetResult.Succeeded)
                throw new ArgumentException($"Password reset failed: {string.Join(", ", resetResult.Errors)}");

            return Result<string>.Ok("Password reset successful.", "Reset password succeeded");
        }
    }
}
