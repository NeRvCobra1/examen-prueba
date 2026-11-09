using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.EntityFrameworkCore;

namespace ExamenPrueba.Infrastructure.Security;

public sealed class PermissionService(ApplicationDbContext dbContext) : IPermissionService
{
    public async Task<IReadOnlyList<string>> GetEffectiveCodesAsync(string userId, CancellationToken cancellationToken = default)
    {
        return await (
            from userRole in dbContext.UserRoles.AsNoTracking()
            join rolePermission in dbContext.RolePermissions.AsNoTracking()
                on userRole.RoleId equals rolePermission.RoleId
            join permission in dbContext.Permissions.AsNoTracking()
                on rolePermission.PermissionId equals permission.Id
            where userRole.UserId == userId
            select permission.Code)
            .Distinct()
            .OrderBy(code => code)
            .ToListAsync(cancellationToken);
    }
}
