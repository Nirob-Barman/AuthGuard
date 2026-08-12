using AuthGuard.Application.DTOs.Audit;
using AuthGuard.Application.Wrappers;
using MediatR;

namespace AuthGuard.Application.Features.Audit.Queries
{
    public record GetLoginAuditsQuery(int PageNumber, int PageSize) : IRequest<Result<PagedResult<LoginAuditResponse>>>;
}
