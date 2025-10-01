using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Interfaces.Email;
using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using System.Net;

namespace AuthGuard.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUserManager _userManager;
        private readonly IRoleManager _roleManager;
        private readonly ISignInManager _signInManager;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly IEmailService _emailService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IUserContextService _userContextService;
        private readonly IRepository<LoginAudit> _loginAuditRepository;
        private readonly IRepository<RefreshToken> _refreshTokenRepository;

        public AuthService(
            IUserManager userManager,
            IRoleManager roleManager,
            ISignInManager signInManager,
            IJwtTokenGenerator jwtTokenGenerator,
            IEmailService emailService, 
            IUnitOfWork unitOfWork,
            IUserContextService userContextService,
            IRepository<LoginAudit> loginAuditRepository,
            IRepository<RefreshToken> refreshTokenRepository)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _jwtTokenGenerator = jwtTokenGenerator;
            _emailService = emailService;
            _unitOfWork = unitOfWork;
            _userContextService = userContextService;
            _loginAuditRepository = loginAuditRepository;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<Result<RegisterResponse>> RegisterAsync(RegisterRequest request)
        {

            var validationErrors = RegisterRequestValidator.Validate(request);
            if (validationErrors.Any())
            {
                return Result<RegisterResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            }

            //if (!_userContextService.IsAuthenticated)
            //{
            //    return Result<RegisterResponse>.Fail("You must be logged in as an Admin to register new users.", "You must be logged in as an Admin to register new users.", ResultType.Unauthorized);
            //}

            //if (!_userContextService.IsInRole("Admin"))
            //{
            //    return Result<RegisterResponse>.Fail("Only Admins can register new users.");
            //}

            //if (request.Role.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            //{
            //    return Result<RegisterResponse>.Fail("Registration failed", "You are not allowed to assign the 'Admin' role.", ResultType.Unauthorized);
            //}

            var existingUser = await _userManager.FindByEmailAsync(request.Email!);
            if (existingUser != null)
                return Result<RegisterResponse>.Fail("A user with this email already exists.", "Registration failed", ResultType.Conflict);

            var user = new ApplicationUser
            {
                Id = string.Empty,
                Email = request.Email,
            };

            await _unitOfWork.BeginTransaction();

            var (success, userId, errors) = await _userManager.CreateAsync(user, request.Password!);
            if (!success)
            {
                await _unitOfWork.RollbackAsync();
                return Result<RegisterResponse>.Fail($"User creation failed: {string.Join(", ", errors)}", "Registration failed", ResultType.ValidationError);
            }


            var createdUser = await _userManager.FindByIdAsync(userId!);
            if (createdUser == null)
            {
                await _unitOfWork.RollbackAsync();
                return Result<RegisterResponse>.Fail("User creation failed: unable to fetch user after creation.", "Registration failed", ResultType.Failure);
            }                


            if (!string.IsNullOrWhiteSpace(request.Role))
            {
                var (roleAssignSuccess, roleErrors) = await _userManager.AddToRoleAsync(createdUser, request.Role!);
                if (!roleAssignSuccess)
                {
                    await _unitOfWork.RollbackAsync();
                    return Result<RegisterResponse>.Fail($"User created but role assignment failed: {string.Join(", ", roleErrors)}", "Role assignment failed", ResultType.Failure);
                }
            }

            await _unitOfWork.CommitAsync();

            var registerResponse = new RegisterResponse
            {
                Id = userId!,
                Email = request.Email!,
                Role = request.Role
            };

            return Result<RegisterResponse>.Ok(registerResponse, "User registered successfully", ResultType.Success);
        }

        public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request)
        {
            var validationErrors = LoginRequestValidator.Validate(request);
            if (validationErrors.Any())
            {
                return Result<AuthResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            }

            await _unitOfWork.BeginTransaction();

            var user = await _userManager.FindByEmailAsync(request.Email!);

            var loginAudit = new LoginAudit
            {
                UserId = user?.Id,
                LoginTime = DateTime.UtcNow,
                Succeeded = false, // Will be updated after password check
                IpAddress = _userContextService.IpAddress,
                UserAgent = _userContextService.UserAgent,
            };

            if (user == null)
            {
                await _loginAuditRepository.AddAsync(loginAudit);
                await _unitOfWork.CommitAsync();
                return Result<AuthResponse>.Fail("Invalid username", "Invalid username", ResultType.Unauthorized);
            }

            var passwordValid = await _signInManager.CheckPasswordSignInAsync(user, request.Password!);

            loginAudit.Succeeded = passwordValid;
            await _loginAuditRepository.AddAsync(loginAudit);

            if (!passwordValid)
            {
                await _unitOfWork.CommitAsync();
                return Result<AuthResponse>.Fail("Invalid password", "Invalid password", ResultType.Unauthorized);
            }

            var refreshToken = _jwtTokenGenerator.GenerateRefreshToken();
            var refreshEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user?.Id,
                ExpiresAt = DateTime.UtcNow.AddDays(30),
                IsRevoked = false
            };
            await _refreshTokenRepository.AddAsync(refreshEntity);

            var (jwtToken, expiresAt) = await _jwtTokenGenerator.GenerateTokenAsync(user!);
            
            await _unitOfWork.CommitAsync();

            var response = new AuthResponse
            {
                AccessToken = jwtToken,
                ExpiresAt = expiresAt,
                RefreshToken = refreshToken,
                Email = user!.Email!,
            };

            return Result<AuthResponse>.Ok(response, "Login successful", ResultType.Success);
        }

        public async Task<Result<UserProfileResponse>> GetCurrentUserAsync()
        {
            var userId = _userContextService.UserId;

            if (string.IsNullOrEmpty(userId))
            {
                return Result<UserProfileResponse>.Fail("User not found", "User ID not found.", ResultType.NotFound);
            }
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return Result<UserProfileResponse>.Fail("User not found.", "User not found", ResultType.NotFound);
            }

            var roles = await _userManager.GetRolesAsync(user);

            var userProfileResponse = new UserProfileResponse
            {
                Id = user?.Id!,
                Email = user?.Email!,
                Roles = roles.ToList()
            };

            return Result<UserProfileResponse>.Ok(userProfileResponse, "User profile retrieved successfully", ResultType.Success);
        }


        public async Task<Result<AuthResponse>> RefreshTokenAsync(RefreshTokenRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateRefreshTokenRequest(request);
            if (validationErrors.Any())
            {
                return Result<AuthResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            }

            await _unitOfWork.BeginTransaction();

            try
            {
                var tokenEntity = await _refreshTokenRepository.FirstOrDefaultAsync(r => r.Token == request.RefreshToken);

                if (tokenEntity == null)
                    return Result<AuthResponse>.Fail("Refresh token not found", "Refresh token not found", ResultType.NotFound);

                if (tokenEntity.IsRevoked)
                    return Result<AuthResponse>.Fail("Refresh token revoked", "Refresh token not found", ResultType.Unauthorized);

                if (tokenEntity.ExpiresAt < DateTime.UtcNow)
                    return Result<AuthResponse>.Fail("Refresh token expired", "Refresh token not found", ResultType.Unauthorized);

                tokenEntity.IsRevoked = true;
                _refreshTokenRepository.Update(tokenEntity);

                var newRefreshToken = _jwtTokenGenerator.GenerateRefreshToken();
                var newRefreshEntity = new RefreshToken
                {
                    UserId = tokenEntity.UserId,
                    Token = newRefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddDays(30),
                    IsRevoked = false
                };

                await _refreshTokenRepository.AddAsync(newRefreshEntity);                

                var user = await _userManager.FindByIdAsync(tokenEntity.UserId!);
                if (user == null) return Result<AuthResponse>.Fail("User not found", "Refresh token not found", ResultType.NotFound);
                
                var (jwtToken, expiresAt) = await _jwtTokenGenerator.GenerateTokenAsync(user!);

                await _unitOfWork.CommitAsync();

                var response = new AuthResponse
                {
                    AccessToken = jwtToken,
                    ExpiresAt = expiresAt,
                    RefreshToken = newRefreshToken
                };

                return Result<AuthResponse>.Ok(response, "Token refreshed successfully", ResultType.Success);
            }
            catch
            {
                await _unitOfWork.RollbackAsync();
                throw;
            }
        }


        public async Task<Result<string>> LogoutAsync(LogoutRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return Result<string>.Fail("Refresh token must not be empty.", "Validation failed", ResultType.ValidationError);
            }

            var tokenEntity = await _refreshTokenRepository.FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

            if (tokenEntity == null || tokenEntity.IsRevoked || tokenEntity.ExpiresAt < DateTime.UtcNow)
                return Result<string>.Fail("Invalid refresh token.", "Invalid refresh token", ResultType.Unauthorized);

            tokenEntity.IsRevoked = true;
            _refreshTokenRepository.Update(tokenEntity);

            await _unitOfWork.CommitAsync();

            return Result<string>.Ok("Logout successful.", "Logout succeeded", ResultType.Success);
        }



        public async Task<Result<string>> RequestPasswordResetAsync(string email)
        {
            var validationErrors = IdentityRequestValidator.ValidatePasswordResetRequestEmail(email);
            if (validationErrors.Any())
            {
                return Result<string>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            }
            
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return Result<string>.Fail("User with the specified email does not exist.", "User with the specified email does not exist", ResultType.NotFound);

            // Generate password reset token
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            if(resetToken == null)
                return Result<string>.Fail("Failed to generate password reset token.", "Request failed", ResultType.Unauthorized);

            var resetLink = $"https://yourfrontend/reset-password?email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(resetToken)}";
            //var resetLink = $"https://yourfrontend.com/reset-password?email={WebUtility.UrlEncode(email)}&token={WebUtility.UrlEncode(resetToken)}";

            var emailBody = $"Click the link below to reset your password:<br><a href='{resetLink}'>Reset Password</a>";

            await _emailService.SendEmailAsync(email, "Password Reset Request", emailBody);

            return Result<string>.Ok("Password reset email sent.", "Request succeeded", ResultType.Success);
        }

        public async Task<Result<string>> ResetPasswordAsync(ResetPasswordRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateResetPasswordRequest(request);
            if (validationErrors.Any())
            {
                return Result<string>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            }

            var user = await _userManager.FindByEmailAsync(request.Email!);
            if (user == null)
                return Result<string>.Fail("User not found.", "User not found", ResultType.NotFound);

            var resetResult = await _userManager.ResetPasswordAsync(user, request.Token!, request.NewPassword!);

            if (!resetResult.Succeeded)
            {
                return Result<string>.Fail($"Password reset failed: {string.Join(", ", resetResult.Errors)}", "Reset password failed", ResultType.ValidationError);
            }

            return Result<string>.Ok("Password reset successful.", "Reset password succeeded", ResultType.Success);
        }

        public async Task<Result<RoleActionResponse>> CreateRoleAsync(CreateRoleRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateCreateRoleRequest(request);
            if (validationErrors.Any())
                return Result<RoleActionResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            
            var exists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (exists)
                return Result<RoleActionResponse>.Fail("Role already exists.", "Role already exists.", ResultType.Conflict);

            var (success, errors) = await _roleManager.CreateRoleAsync(request.RoleName!);

            if (!success)
                return Result<RoleActionResponse>.Fail(errors, "Role creation failed", ResultType.ValidationError);

            var response = new RoleActionResponse { RoleName = request.RoleName };
            return Result<RoleActionResponse>.Ok(response, "Role created successfully", ResultType.Success);
        }

        public async Task<Result<RoleActionResponse>> DeleteRoleAsync(DeleteRoleRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateDeleteRoleRequest(request);
            if (request == null || validationErrors.Any())
                return Result<RoleActionResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);
            
            //var roleExists = await _userManager.RoleExistsAsync(request.RoleName);
            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName);
            if (!roleExists)
                return Result<RoleActionResponse>.Fail("Role does not exist.", "Delete role failed", ResultType.NotFound);

            //var result = await _userManager.DeleteRoleAsync(request.RoleName);
            //if (!result.Succeeded)
            //    return Result<RoleActionResponse>.Fail($"Role deletion failed: {string.Join(", ", result.Errors)}", "Delete role failed", ResultType.ValidationError);

            //var response = new RoleActionResponse { RoleName = request.RoleName };

            //return Result<RoleActionResponse>.Ok(response, "Role deleted successfully", ResultType.Success);


            var (success, errors) = await _roleManager.DeleteRoleAsync(request.RoleName);

            if (!success)
                return Result<RoleActionResponse>.Fail(errors, "Role deletion failed", ResultType.ValidationError);

            var response = new RoleActionResponse { RoleName = request.RoleName };
            return Result<RoleActionResponse>.Ok(response, "Role deleted successfully", ResultType.Success);

        }

        public async Task<Result<RoleAssignmentResponse>> AssignRoleAsync(AssignRoleRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateAssignRoleRequest(request);
            if (request == null || validationErrors.Any())
                return Result<RoleAssignmentResponse>.Fail(validationErrors,"Validation failed", ResultType.ValidationError);
            
            var user = await _userManager.FindByIdAsync(request.UserId!);
            if (user == null)
                return Result<RoleAssignmentResponse>.Fail("User not found.", "Assign role failed", ResultType.NotFound);

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName!);
            if (!roleExists)
                return Result<RoleAssignmentResponse>.Fail("Role does not exist.", "Assign role failed", ResultType.NotFound);
           

            var (success, errors) = await _userManager.AddToRoleAsync(user, request.RoleName!);

            if (!success)
                return Result<RoleAssignmentResponse>.Fail(errors, "Role assignment failed", ResultType.ValidationError);
            var response = new RoleAssignmentResponse { UserId = request.UserId, RoleName = request.RoleName };

            return Result<RoleAssignmentResponse>.Ok(response, "Role assigned successfully", ResultType.Success);
        }

        public async Task<Result<RoleRemovalResponse>> RemoveRoleAsync(RemoveRoleRequest request)
        {
            var validationErrors = IdentityRequestValidator.ValidateRemoveRoleRequest(request);
            if (request == null || validationErrors.Any())
                return Result<RoleRemovalResponse>.Fail(validationErrors, "Validation failed", ResultType.ValidationError);

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null)
                return Result<RoleRemovalResponse>.Fail("User not found.", "Remove role failed", ResultType.NotFound);

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName);
            if (!roleExists)
                return Result<RoleRemovalResponse>.Fail("Role does not exist.", "Remove role failed", ResultType.NotFound);

            var result = await _userManager.RemoveFromRoleAsync(user, request.RoleName);
            if (!result.Succeeded)
                return Result<RoleRemovalResponse>.Fail($"Role removal failed: {string.Join(", ", result.Errors)}", "Remove role failed", ResultType.ValidationError);

            var response = new RoleRemovalResponse { UserId = request.UserId, RoleName = request.RoleName };

            return Result<RoleRemovalResponse>.Ok(response, "Role removed successfully", ResultType.Success);
        }
    }
}
