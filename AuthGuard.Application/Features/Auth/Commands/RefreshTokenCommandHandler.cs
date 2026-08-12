using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, Result<AuthResponse>>
    {
        private readonly IUserManager _userManager;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly IRepository<RefreshToken> _refreshTokenRepository;

        public RefreshTokenCommandHandler(
            IUserManager userManager,
            IJwtTokenGenerator jwtTokenGenerator,
            IRepository<RefreshToken> refreshTokenRepository)
        {
            _userManager = userManager;
            _jwtTokenGenerator = jwtTokenGenerator;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<Result<AuthResponse>> Handle(RefreshTokenCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = IdentityRequestValidator.ValidateRefreshTokenRequest(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            var tokenEntity = await _refreshTokenRepository.FirstOrDefaultAsync(r => r.Token == request.RefreshToken);

            if (tokenEntity == null)
                throw new KeyNotFoundException("Refresh token not found");

            if (tokenEntity.IsRevoked)
                throw new UnauthorizedAccessException("Refresh token revoked");

            if (tokenEntity.ExpiresAt < DateTime.UtcNow)
                throw new UnauthorizedAccessException("Refresh token expired");

            tokenEntity.Revoke();
            _refreshTokenRepository.Update(tokenEntity);

            var newRefreshToken = _jwtTokenGenerator.GenerateRefreshToken();
            var newRefreshEntity = RefreshToken.Issue(tokenEntity.UserId, newRefreshToken, DateTime.UtcNow.AddDays(30));
            await _refreshTokenRepository.AddAsync(newRefreshEntity);

            var user = await _userManager.FindByIdAsync(tokenEntity.UserId!);
            if (user == null)
                throw new KeyNotFoundException("User not found");

            var (jwtToken, expiresAt) = await _jwtTokenGenerator.GenerateTokenAsync(user);

            var response = new AuthResponse
            {
                AccessToken = jwtToken,
                ExpiresAt = expiresAt,
                RefreshToken = newRefreshToken
            };

            return Result<AuthResponse>.Ok(response, "Token refreshed successfully");
        }
    }
}
