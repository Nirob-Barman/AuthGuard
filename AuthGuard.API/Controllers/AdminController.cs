using AuthGuard.API.Wrappers;
using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthGuard.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly IAuthService _authService;
        public AdminController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            var result = await _authService.CreateRoleAsync(request);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }

        [HttpPost("delete-role")]
        public async Task<IActionResult> DeleteRole([FromBody] DeleteRoleRequest request)
        {
            var result = await _authService.DeleteRoleAsync(request);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
        {
            var result = await _authService.AssignRoleAsync(request);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }
        [HttpPost("remove-role")]
        public async Task<IActionResult> RemoveRole([FromBody] RemoveRoleRequest request)
        {
            var result = await _authService.RemoveRoleAsync(request);
            //return StatusCode(result.StatusCode, result);
            return ApiResponseMapper.FromResult(this, result);
        }
    }
}