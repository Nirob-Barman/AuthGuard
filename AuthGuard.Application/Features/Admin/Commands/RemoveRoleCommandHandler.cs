using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public class RemoveRoleCommandHandler : IRequestHandler<RemoveRoleCommand, Result<RoleRemovalResponse>>
    {
        private readonly IUserManager _userManager;
        private readonly IRoleManager _roleManager;

        public RemoveRoleCommandHandler(IUserManager userManager, IRoleManager roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<Result<RoleRemovalResponse>> Handle(RemoveRoleCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateRemoveRoleRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var user = await _userManager.FindByIdAsync(request.UserId!);
            if (user == null)
                throw new KeyNotFoundException("User not found.");

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (!roleExists)
                throw new KeyNotFoundException("Role does not exist.");

            var result = await _userManager.RemoveFromRoleAsync(user, request.RoleName!);
            if (!result.Succeeded)
                throw new ArgumentException($"Role removal failed: {string.Join(", ", result.Errors)}");

            var response = new RoleRemovalResponse { UserId = request.UserId, RoleName = request.RoleName };
            return Result<RoleRemovalResponse>.Ok(response, "Role removed successfully");
        }
    }
}
