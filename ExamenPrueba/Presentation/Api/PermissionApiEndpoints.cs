using System.Security.Claims;
using ExamenPrueba.Application.Permissions;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Infrastructure.Security;

namespace ExamenPrueba.Presentation.Api;

public static class PermissionApiEndpoints
{
    public static IEndpointRouteBuilder MapPermissionApi(this IEndpointRouteBuilder endpoints)
    {
        var permissions = endpoints.MapGroup("/api/permissions");

        permissions.MapGet("", async (
            int? page, int? pageSize, string? search, IPermissionManagementService service,
            CancellationToken cancellationToken) =>
        {
            var requestedPage = page ?? 1;
            var requestedPageSize = pageSize ?? 10;
            if (requestedPage is < 1 or > 100000 || requestedPageSize is < 1 or > 50 || search?.Length > 128)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["pagination"] =
                    ["Page debe estar entre 1 y 100000, PageSize entre 1 y 50 y Search no debe superar 128 caracteres."]
                });
            }

            return Results.Ok(await service.ListAsync(
                requestedPage, requestedPageSize, search, cancellationToken));
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.PermissionsRead))
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeRead);

        permissions.MapGet("/{id:int}", async (
            int id, IPermissionManagementService service, CancellationToken cancellationToken) =>
        {
            var permission = await service.GetAsync(id, cancellationToken);
            return permission is null ? Results.NotFound() : Results.Ok(permission);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.PermissionsRead))
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeRead);

        permissions.MapPost("", async (
            CreatePermissionRequest request, IPermissionManagementService service,
            CancellationToken cancellationToken) =>
        {
            var result = await service.CreateAsync(request, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.Created($"/api/permissions/{result.Permission!.Id}", result.Permission)
                : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.PermissionsCreate))
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeMutation)
            .ValidateApiAntiforgery();

        permissions.MapPut("/{id:int}", async (
            int id, UpdatePermissionRequest request, IPermissionManagementService service,
            CancellationToken cancellationToken) =>
        {
            var result = await service.UpdateAsync(id, request, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.Ok(result.Permission) : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.PermissionsUpdate))
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeMutation)
            .ValidateApiAntiforgery();

        permissions.MapDelete("/{id:int}", async (
            int id, IPermissionManagementService service, CancellationToken cancellationToken) =>
        {
            var result = await service.DeleteAsync(id, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.NoContent() : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.PermissionsDelete))
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeMutation)
            .ValidateApiAntiforgery();

        endpoints.MapGet("/api/roles/{roleId}/permissions", async (
            string roleId, IPermissionManagementService service, CancellationToken cancellationToken) =>
        {
            var result = await service.GetRolePermissionsAsync(roleId, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.Ok(result.RolePermissions) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.RolePermissionsRead)
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeRead);

        endpoints.MapPost("/api/roles/{roleId}/permissions/{permissionId:int}", async (
            string roleId, int permissionId, ClaimsPrincipal principal,
            IPermissionManagementService service, CancellationToken cancellationToken) =>
        {
            var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null)
            {
                return Results.Unauthorized();
            }

            var result = await service.AssignToRoleAsync(
                roleId, permissionId, actorId, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.Ok(result.RolePermissions) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.RolePermissionsManage)
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeMutation)
            .ValidateApiAntiforgery();

        endpoints.MapDelete("/api/roles/{roleId}/permissions/{permissionId:int}", async (
            string roleId, int permissionId, ClaimsPrincipal principal,
            IPermissionManagementService service, CancellationToken cancellationToken) =>
        {
            var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null)
            {
                return Results.Unauthorized();
            }

            var result = await service.RevokeFromRoleAsync(
                roleId, permissionId, actorId, cancellationToken);
            return result.Kind == PermissionManagementResultKind.Success
                ? Results.Ok(result.RolePermissions) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.RolePermissionsManage)
            .RequireRateLimiting(RateLimitPolicyNames.AdministrativeMutation)
            .ValidateApiAntiforgery();

        return endpoints;
    }

    private static IResult ToError(PermissionManagementResult result) => result.Kind switch
    {
        PermissionManagementResultKind.Validation => Results.ValidationProblem(result.Errors!),
        PermissionManagementResultKind.Conflict => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Conflicto de permiso.",
            detail: result.Message ?? string.Join(" ", result.Errors?.Values.SelectMany(value => value) ?? [])),
        PermissionManagementResultKind.NotFound => Results.Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "Recurso no encontrado.",
            detail: result.Message),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
    };
}
