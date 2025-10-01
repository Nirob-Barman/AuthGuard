using AuthGuard.API.Wrappers;
using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthGuard.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        //[Authorize]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request);
            return ApiResponseMapper.FromResult(this, result);

        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await _authService.LoginAsync(request);
            return ApiResponseMapper.FromResult(this, result);
        }

        [Authorize]
        //[AllowAnonymous]
        [HttpGet("me")]
        public async Task<IActionResult> Me()
        {
            var result = await _authService.GetCurrentUserAsync();
            return ApiResponseMapper.FromResult(this, result);
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _authService.RefreshTokenAsync(request);
            return ApiResponseMapper.FromResult(this, result);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
        {
            //var restult = await _authService.LogoutAsync(request.RefreshToken!);
            var restult = await _authService.LogoutAsync(request);
            //return StatusCode(restult.StatusCode, restult);
            return ApiResponseMapper.FromResult(this, restult);
        }


        [HttpPost("request-password-reset")]
        public async Task<IActionResult> RequestPasswordReset([FromBody] PasswordResetRequest request)
        {
            var result = await _authService.RequestPasswordResetAsync(request.Email!);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var result = await _authService.ResetPasswordAsync(request);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }
    }
}
