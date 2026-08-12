using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public record RequestPasswordResetCommand(string Email) : IRequest<Result<string>>;
}
