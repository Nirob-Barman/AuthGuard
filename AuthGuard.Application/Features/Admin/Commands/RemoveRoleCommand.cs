using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public record RemoveRoleCommand(RemoveRoleRequest Request) : IRequest<Result<RoleRemovalResponse>>;
}
