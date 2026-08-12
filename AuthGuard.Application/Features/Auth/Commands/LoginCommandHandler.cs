using AuthGuard.Application.DTOs.Auth;
using AuthGuard.Application.Interfaces;
using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Validators.Auth;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using MediatR;

namespace AuthGuard.Application.Features.Auth.Commands
{
    public class LoginCommandHandler : IRequestHandler<LoginCommand, Result<AuthResponse>>
    {
        private readonly IUserManager _userManager;
        private readonly ISignInManager _signInManager;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly IUserContextService _userContextService;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IRepository<LoginAudit> _loginAuditRepository;
        private readonly IRepository<RefreshToken> _refreshTokenRepository;

        public LoginCommandHandler(
            IUserManager userManager,
            ISignInManager signInManager,
            IJwtTokenGenerator jwtTokenGenerator,
            IUserContextService userContextService,
            IUnitOfWork unitOfWork,
            IRepository<LoginAudit> loginAuditRepository,
            IRepository<RefreshToken> refreshTokenRepository)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenGenerator = jwtTokenGenerator;
            _userContextService = userContextService;
            _unitOfWork = unitOfWork;
            _loginAuditRepository = loginAuditRepository;
            _refreshTokenRepository = refreshTokenRepository;
        }

        public async Task<Result<AuthResponse>> Handle(LoginCommand command, CancellationToken cancellationToken)
        {
            var request = command.Request;

            var validationErrors = LoginRequestValidator.Validate(request);
            if (validationErrors.Any())
                throw new ArgumentException(string.Join(" ", validationErrors));

            await _unitOfWork.BeginTransaction();

            var user = await _userManager.FindByEmailAsync(request.Email!);

            if (user == null)
            {
                var missingUserAudit = LoginAudit.Record(null, _userContextService.IpAddress, _userContextService.UserAgent, false);
                await _loginAuditRepository.AddAsync(missingUserAudit);
                await _unitOfWork.CommitAsync();
                throw new UnauthorizedAccessException("Invalid username");
            }

            var passwordValid = await _signInManager.CheckPasswordSignInAsync(user, request.Password!);

            var loginAudit = LoginAudit.Record(user.Id, _userContextService.IpAddress, _userContextService.UserAgent, passwordValid);
            await _loginAuditRepository.AddAsync(loginAudit);

            if (!passwordValid)
            {
                await _unitOfWork.CommitAsync();
                throw new UnauthorizedAccessException("Invalid password");
            }

            var refreshToken = _jwtTokenGenerator.GenerateRefreshToken();
            var refreshEntity = RefreshToken.Issue(user.Id, refreshToken, DateTime.UtcNow.AddDays(30));
            await _refreshTokenRepository.AddAsync(refreshEntity);

            var (jwtToken, expiresAt) = await _jwtTokenGenerator.GenerateTokenAsync(user);

            await _unitOfWork.CommitAsync();

            var response = new AuthResponse
            {
                AccessToken = jwtToken,
                ExpiresAt = expiresAt,
                RefreshToken = refreshToken,
                Email = user.Email!,
            };

            return Result<AuthResponse>.Ok(response, "Login successful");
        }
    }
}
