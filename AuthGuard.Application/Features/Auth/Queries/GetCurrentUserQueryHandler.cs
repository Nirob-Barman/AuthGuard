using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Queries
{
    public class GetCurrentUserQueryHandler : IRequestHandler<GetCurrentUserQuery, Result<UserProfileResponse>>
    {
        private readonly IUserContextService _userContextService;
        private readonly IUserManager _userManager;

        public GetCurrentUserQueryHandler(IUserContextService userContextService, IUserManager userManager)
        {
            _userContextService = userContextService;
            _userManager = userManager;
        }

        public async Task<Result<UserProfileResponse>> Handle(GetCurrentUserQuery request, CancellationToken cancellationToken)
        {
            var userId = _userContextService.UserId;
            if (string.IsNullOrEmpty(userId))
                throw new KeyNotFoundException("User ID not found.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new KeyNotFoundException("User not found.");

            var roles = await _userManager.GetRolesAsync(user);

            var userProfileResponse = new UserProfileResponse
            {
                Id = user.Id!,
                Email = user.Email!,
                Roles = roles.ToList()
            };

            return Result<UserProfileResponse>.Ok(userProfileResponse, "User profile retrieved successfully");
        }
    }
}
