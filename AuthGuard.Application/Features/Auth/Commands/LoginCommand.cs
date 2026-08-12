using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    // Deliberately not ITransactionalRequest: a failed login (bad username/password) must
    // still commit its LoginAudit row for security monitoring, so this handler manages its
    // own transaction rather than relying on the pipeline's rollback-on-exception behavior.
    public record LoginCommand(LoginRequest Request) : IRequest<Result<AuthResponse>>;
}
