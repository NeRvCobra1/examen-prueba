using System.Security.Claims;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;

namespace ExamenPrueba.Presentation.Api;

public static class SecurityApiEndpoints
{
    public static IEndpointRouteBuilder MapSecurityApi(this IEndpointRouteBuilder endpoints)
    {
        var api = endpoints.MapGroup("/api");

        api.MapGet("/auth/me", async (ClaimsPrincipal principal, UserManager<ApplicationUser> userManager) =>
        {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = userId is null ? null : await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return Results.Unauthorized();
            }

            var roles = await userManager.GetRolesAsync(user);
            return Results.Ok(new MeDto(user.Id, user.Email, roles.OrderBy(role => role).ToArray()));
        }).RequireAuthorization();

        api.MapGet("/security/capabilities", async (ClaimsPrincipal principal, IPermissionService permissionService) =>
        {
            var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            return Results.Ok(await permissionService.GetEffectiveCodesAsync(userId));
        }).RequireAuthorization();

        api.MapGet("/security/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var token = antiforgery.GetAndStoreTokens(context).RequestToken;
            return Results.Ok(new AntiforgeryDto(token));
        }).RequireAuthorization();

        api.MapGet("/admin/overview", () => Results.Ok(new AdminOverviewDto("Acceso administrativo verificado.")))
            .RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersRead));

        return endpoints;
    }

    public sealed record MeDto(string Id, string? Email, IReadOnlyList<string> Roles);
    public sealed record AdminOverviewDto(string Message);
    public sealed record AntiforgeryDto(string? Token);
}
