using AuthGuard.Application.DTOs.Admin;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Admin.Commands
{
    public record AssignRoleCommand(AssignRoleRequest Request) : IRequest<Result<RoleAssignmentResponse>>;
}
