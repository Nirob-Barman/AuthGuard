using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public class AssignRoleCommandHandler : IRequestHandler<AssignRoleCommand, Result<RoleAssignmentResponse>>
    {
        private readonly IUserManager _userManager;
        private readonly IRoleManager _roleManager;

        public AssignRoleCommandHandler(IUserManager userManager, IRoleManager roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<Result<RoleAssignmentResponse>> Handle(AssignRoleCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateAssignRoleRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var user = await _userManager.FindByIdAsync(request.UserId!);
            if (user == null)
                throw new KeyNotFoundException("User not found.");

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (!roleExists)
                throw new KeyNotFoundException("Role does not exist.");

            var (success, errors) = await _userManager.AddToRoleAsync(user, request.RoleName!);
            if (!success)
                throw new ArgumentException($"Role assignment failed: {string.Join(", ", errors)}");

            var response = new RoleAssignmentResponse { UserId = request.UserId, RoleName = request.RoleName };
            return Result<RoleAssignmentResponse>.Ok(response, "Role assigned successfully");
        }
    }
}
