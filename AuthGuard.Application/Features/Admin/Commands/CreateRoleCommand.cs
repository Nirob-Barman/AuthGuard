using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public record CreateRoleCommand(CreateRoleRequest Request) : IRequest<Result<RoleActionResponse>>;
}
