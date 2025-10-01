using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Wrappers;


namespace AuthGuard.Application.Services
{
    public interface IAuthService
    {
        Task<Result<RegisterResponse>> RegisterAsync(RegisterRequest request);
        Task<Result<AuthResponse>> LoginAsync(LoginRequest request);
        //Task<ApiResponse<UserProfileResponse>> GetCurrentUserAsync(ClaimsPrincipal user);
        Task<Result<UserProfileResponse>> GetCurrentUserAsync();
        Task<Result<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request);
        Task<Result<string>> LogoutAsync(LogoutRequest request);
        Task<Result<string>> RequestPasswordResetAsync(string email);
        Task<Result<string>> ResetPasswordAsync(ResetPasswordRequest request);

        Task<Result<RoleActionResponse>> CreateRoleAsync(CreateRoleRequest request);
        Task<Result<RoleActionResponse>> DeleteRoleAsync(DeleteRoleRequest request);
        Task<Result<RoleAssignmentResponse>> AssignRoleAsync(AssignRoleRequest request);
        Task<Result<RoleRemovalResponse>> RemoveRoleAsync(RemoveRoleRequest request);
    }
}
