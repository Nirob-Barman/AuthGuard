using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Features.Admin.Commands;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthGuard.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class AdminController : ControllerBase
    {
        private readonly IMediator _mediator;
        public AdminController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleRequest request)
        {
            var result = await _mediator.Send(new CreateRoleCommand(request));
            return Ok(result.Data);
        }

        [HttpPost("delete-role")]
        public async Task<IActionResult> DeleteRole([FromBody] DeleteRoleRequest request)
        {
            var result = await _mediator.Send(new DeleteRoleCommand(request));
            return Ok(result.Data);
        }

        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleRequest request)
        {
            var result = await _mediator.Send(new AssignRoleCommand(request));
            return Ok(result.Data);
        }

        [HttpPost("remove-role")]
        public async Task<IActionResult> RemoveRole([FromBody] RemoveRoleRequest request)
        {
            var result = await _mediator.Send(new RemoveRoleCommand(request));
            return Ok(result.Data);
        }
    }
}
