using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class LogoutCommandHandler : IRequestHandler<LogoutCommand, Result<string>>
    {
        private readonly IRepository<RefreshToken> _refreshTokenRepository;

        public LogoutCommandHandler(IRepository<RefreshToken> refreshTokenRepository)
        {
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<Result<string>> Handle(LogoutCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            if (string.IsNullOrWhiteSpace(request.RefreshToken))
                throw new ArgumentException("Refresh token must not be empty.");

            var tokenEntity = await _refreshTokenRepository.FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

            if (tokenEntity == null || !tokenEntity.IsActive)
                throw new UnauthorizedAccessException("Invalid refresh token.");

            tokenEntity.Revoke();
            _refreshTokenRepository.Update(tokenEntity);

            return Result<string>.Ok("Logout successful.", "Logout succeeded");
        }
    }
}
