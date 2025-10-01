//using AuthGuard.Application.DTOs.Admin;
//using AuthGuard.Application.DTOs.Auth;
//using AuthGuard.Application.Wrappers;
//using AuthGuard.Domain.Entities;
//using System.Security.Claims;

//namespace AuthGuard.Application.Interfaces
//{
//    public interface IIdentityService
//    {
//        Task<Result<RegisterResponse>> RegisterAsync(RegisterRequest request);
//        //Task<(bool Success, ApplicationUser? User, IList<string>? Roles, List<string> Errors)> ValidateCredentialsAsync(string email, string password)
//        Task<(bool Success, JwtUserInfo? UserInfo, IList<string> Roles, List<string> Errors)> ValidateCredentialsAsync(string email, string password);
//        //Task<Result<AuthResponse>> LoginAsync(LoginRequest request);
//        //Task LogLoginAuditAsync(ApplicationUser user);
//        Task<ApiResponse<UserProfileResponse>> GetCurrentUserAsync(ClaimsPrincipal user);
//        Task<Result<UserProfileResponse>> GetUserProfileAsync(string userId);
//        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request);
//        Task<ApiResponse<string>> LogoutAsync(string refreshToken);
//        Task<ApiResponse<string>> RequestPasswordResetAsync(string email);
//        Task<ApiResponse<string>> ResetPasswordAsync(ResetPasswordRequest request);

//        Task<bool> UserExistsAsync(string email);

//        Task<ApiResponse<RoleActionResponse>> CreateRoleAsync(CreateRoleRequest request);
//        Task<ApiResponse<RoleActionResponse>> DeleteRoleAsync(DeleteRoleRequest request);
//        Task<ApiResponse<RoleAssignmentResponse>> AssignRoleAsync(AssignRoleRequest request);
//        Task<ApiResponse<RoleRemovalResponse>> RemoveRoleAsync(RemoveRoleRequest request);
//    }
//}
