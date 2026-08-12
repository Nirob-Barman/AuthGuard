using AuthGuard.Application.DTOs.Audit;
using AuthGuard.Application.Interfaces.Persistence;
using AuthGuard.Application.Wrappers;
using AuthGuard.Domain.Entities;
using MediatR;

namespace AuthGuard.Application.Features.Audit.Queries
{
    public class GetLoginAuditsQueryHandler : IRequestHandler<GetLoginAuditsQuery, Result<PagedResult<LoginAuditResponse>>>
    {
        private const int DefaultPageSize = 20;
        private const int MaxPageSize = 100;

        private readonly IRepository<LoginAudit> _loginAuditRepository;

        public GetLoginAuditsQueryHandler(IRepository<LoginAudit> loginAuditRepository)
        {
            _loginAuditRepository = loginAuditRepository;
        }

        public async Task<Result<PagedResult<LoginAuditResponse>>> Handle(GetLoginAuditsQuery request, CancellationToken cancellationToken)
        {
            var pageNumber = request.PageNumber < 1 ? 1 : request.PageNumber;
            var pageSize = request.PageSize < 1 ? DefaultPageSize : Math.Min(request.PageSize, MaxPageSize);

            var audits = await _loginAuditRepository.GetPagedAsync(pageNumber, pageSize, a => a.LoginTime, descending: true);
            var totalCount = await _loginAuditRepository.CountAsync();

            var items = audits.Select(a => new LoginAuditResponse
            {
                Id = a.Id,
                UserId = a.UserId,
                LoginTime = a.LoginTime,
                Succeeded = a.Succeeded,
                LogoutTime = a.LogoutTime,
                IpAddress = a.IpAddress,
                UserAgent = a.UserAgent
            });

            var pagedResult = new PagedResult<LoginAuditResponse>
            {
                Items = items,
                PageNumber = pageNumber,
                PageSize = pageSize,
                TotalCount = totalCount
            };

            return Result<PagedResult<LoginAuditResponse>>.Ok(pagedResult, "Login audits retrieved successfully");
        }
    }
}
