using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public class CreateRoleCommandHandler : IRequestHandler<CreateRoleCommand, Result<RoleActionResponse>>
    {
        private readonly IRoleManager _roleManager;

        public CreateRoleCommandHandler(IRoleManager roleManager)
        {
            _roleManager = roleManager;
        }

        public async Task<Result<RoleActionResponse>> Handle(CreateRoleCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateCreateRoleRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var exists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (exists)
                throw new InvalidOperationException("Role already exists.");

            var (success, errors) = await _roleManager.CreateRoleAsync(request.RoleName!);
            if (!success)
                throw new ArgumentException($"Role creation failed: {string.Join(", ", errors)}");

            var response = new RoleActionResponse { RoleName = request.RoleName };
            return Result<RoleActionResponse>.Ok(response, "Role created successfully");
        }
    }
}
