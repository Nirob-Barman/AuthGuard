using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class RegisterCommandHandler : IRequestHandler<RegisterCommand, Result<RegisterResponse>>
    {
        private readonly IUserManager _userManager;

        public RegisterCommandHandler(IUserManager userManager)
        {
            _userManager = userManager;
        }

        public async Task<Result<RegisterResponse>> Handle(RegisterCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = RegisterRequestValidator.Validate(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var existingUser = await _userManager.FindByEmailAsync(request.Email!);
            if (existingUser != null)
                throw new InvalidOperationException("A user with this email already exists.");

            var user = ApplicationUser.Create(request.Email);

            var (success, userId, errors) = await _userManager.CreateAsync(user, request.Password!);
            if (!success)
                throw new ArgumentException($"User creation failed: {string.Join(", ", errors)}");

            if (!string.IsNullOrWhiteSpace(request.Role))
            {
                var (roleAssignSuccess, roleErrors) = await _userManager.AddToRoleAsync(user, request.Role!);
                if (!roleAssignSuccess)
                    throw new ArgumentException($"Role assignment failed: {string.Join(", ", roleErrors)}");
            }

            var registerResponse = new RegisterResponse
            {
                Id = userId!,
                Email = request.Email!,
                Role = request.Role
            };

            return Result<RegisterResponse>.Ok(registerResponse, "User registered successfully");
        }
    }
}
