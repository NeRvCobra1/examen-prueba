using System.Security.Claims;
using ExamenPrueba.Application.Security;
using Microsoft.AspNetCore.Authorization;

namespace ExamenPrueba.Infrastructure.Security;

public sealed class PermissionAuthorizationHandler(IPermissionService permissionService)
    : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true ||
            context.User.FindFirstValue(ClaimTypes.NameIdentifier) is not { } userId)
        {
            return;
        }

        var codes = await permissionService.GetEffectiveCodesAsync(userId);
        if (codes.Contains(requirement.Code, StringComparer.Ordinal))
        {
            context.Succeed(requirement);
        }
    }
}
