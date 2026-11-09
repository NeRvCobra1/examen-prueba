using System.Security.Claims;
using ExamenPrueba.Application.Roles;
using ExamenPrueba.Application.Security;

namespace ExamenPrueba.Presentation.Api;

public static class RoleApiEndpoints
{
    public static IEndpointRouteBuilder MapRoleApi(this IEndpointRouteBuilder endpoints)
    {
        var roles = endpoints.MapGroup("/api/roles");

        roles.MapGet("", async (
            int? page, int? pageSize, string? search, IRoleService service, CancellationToken cancellationToken) =>
        {
            var requestedPage = page ?? 1;
            var requestedPageSize = pageSize ?? 10;
            if (requestedPage is < 1 or > 100000 || requestedPageSize is < 1 or > 50 || search?.Length > 64)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["pagination"] =
                    ["Page debe estar entre 1 y 100000, PageSize entre 1 y 50 y Search no debe superar 64 caracteres."]
                });
            }

            return Results.Ok(await service.ListAsync(
                requestedPage, requestedPageSize, search, cancellationToken));
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.RolesRead));

        roles.MapGet("/{id}", async (string id, IRoleService service, CancellationToken cancellationToken) =>
        {
            var role = await service.GetAsync(id, cancellationToken);
            return role is null ? Results.NotFound() : Results.Ok(role);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.RolesRead));

        roles.MapPost("", async (CreateRoleRequest request, IRoleService service) =>
        {
            var result = await service.CreateAsync(request);
            return result.Kind == RoleResultKind.Success
                ? Results.Created($"/api/roles/{Uri.EscapeDataString(result.Role!.Id)}", result.Role)
                : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.RolesCreate)).ValidateApiAntiforgery();

        roles.MapPut("/{id}", async (string id, UpdateRoleRequest request, IRoleService service) =>
        {
            var result = await service.UpdateAsync(id, request);
            return result.Kind == RoleResultKind.Success ? Results.Ok(result.Role) : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.RolesUpdate)).ValidateApiAntiforgery();

        roles.MapDelete("/{id}", async (string id, IRoleService service, CancellationToken cancellationToken) =>
        {
            var result = await service.DeleteAsync(id, cancellationToken);
            return result.Kind == RoleResultKind.Success ? Results.NoContent() : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.RolesDelete)).ValidateApiAntiforgery();

        endpoints.MapGet("/api/users/{userId}/roles", async (
            string userId, IRoleService service, CancellationToken cancellationToken) =>
        {
            var result = await service.GetUserRolesAsync(userId, cancellationToken);
            return result.Kind == RoleResultKind.Success ? Results.Ok(result.UserRoles) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.UserRolesRead);

        endpoints.MapPost("/api/users/{userId}/roles/{roleId}", async (
            string userId, string roleId, ClaimsPrincipal principal, IRoleService service) =>
        {
            var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null)
            {
                return Results.Unauthorized();
            }

            var result = await service.AssignAsync(userId, roleId, actorId);
            return result.Kind == RoleResultKind.Success ? Results.Ok(result.UserRoles) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.UserRolesManage).ValidateApiAntiforgery();

        endpoints.MapDelete("/api/users/{userId}/roles/{roleId}", async (
            string userId, string roleId, ClaimsPrincipal principal, IRoleService service,
            CancellationToken cancellationToken) =>
        {
            var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null)
            {
                return Results.Unauthorized();
            }

            var result = await service.RevokeAsync(userId, roleId, actorId, cancellationToken);
            return result.Kind == RoleResultKind.Success ? Results.Ok(result.UserRoles) : ToError(result);
        }).RequireAuthorization(SecurityPolicies.UserRolesManage).ValidateApiAntiforgery();

        return endpoints;
    }

    private static IResult ToError(RoleResult result) => result.Kind switch
    {
        RoleResultKind.Validation => Results.ValidationProblem(result.Errors!),
        RoleResultKind.Conflict => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Conflicto de rol.",
            detail: result.Message ?? string.Join(" ", result.Errors?.Values.SelectMany(value => value) ?? [])),
        RoleResultKind.NotFound => Results.Problem(
            statusCode: StatusCodes.Status404NotFound,
            title: "Recurso no encontrado.",
            detail: result.Message),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
    };
}
