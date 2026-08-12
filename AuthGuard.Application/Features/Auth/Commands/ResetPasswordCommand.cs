using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public record ResetPasswordCommand(ResetPasswordRequest Request) : IRequest<Result<string>>;
}
