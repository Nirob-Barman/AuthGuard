using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Features.Common;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public record RegisterCommand(RegisterRequest Request) : ITransactionalRequest, IRequest<Result<RegisterResponse>>;
}
