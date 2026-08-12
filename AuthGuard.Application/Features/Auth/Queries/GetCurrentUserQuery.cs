using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Queries
{
    public record GetCurrentUserQuery : IRequest<Result<UserProfileResponse>>;
}
