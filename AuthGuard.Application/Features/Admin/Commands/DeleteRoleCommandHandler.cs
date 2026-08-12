using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public class DeleteRoleCommandHandler : IRequestHandler<DeleteRoleCommand, Result<RoleActionResponse>>
    {
        private readonly IRoleManager _roleManager;

        public DeleteRoleCommandHandler(IRoleManager roleManager)
        {
            _roleManager = roleManager;
        }

        public async Task<Result<RoleActionResponse>> Handle(DeleteRoleCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateDeleteRoleRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (!roleExists)
                throw new KeyNotFoundException("Role does not exist.");

            var (success, errors) = await _roleManager.DeleteRoleAsync(request.RoleName!);
            if (!success)
                throw new ArgumentException($"Role deletion failed: {string.Join(", ", errors)}");

            var response = new RoleActionResponse { RoleName = request.RoleName };
            return Result<RoleActionResponse>.Ok(response, "Role deleted successfully");
        }
    }
}
