using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Features.Common;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public record LogoutCommand(LogoutRequest Request) : ITransactionalRequest, IRequest<Result<string>>;
}
