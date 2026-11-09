using System.Security.Claims;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Application.Users;

namespace ExamenPrueba.Presentation.Api;

public static class UserApiEndpoints
{
    public static IEndpointRouteBuilder MapUserApi(this IEndpointRouteBuilder endpoints)
    {
        var users = endpoints.MapGroup("/api/users");

        users.MapGet("", async (int? page, int? pageSize, string? search, IUserService service, CancellationToken cancellationToken) =>
        {
            var requestedPage = page ?? 1;
            var requestedPageSize = pageSize ?? 10;
            if (requestedPage is < 1 or > 100000 || requestedPageSize is < 1 or > 50 || search?.Length > 256)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["pagination"] = ["Page debe estar entre 1 y 100000, PageSize entre 1 y 50 y Search no debe superar 256 caracteres."]
                });
            }

            return Results.Ok(await service.ListAsync(requestedPage, requestedPageSize, search, cancellationToken));
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersRead));

        users.MapGet("/{id}", async (string id, IUserService service) =>
        {
            var user = await service.GetAsync(id);
            return user is null ? Results.NotFound() : Results.Ok(user);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersRead));

        users.MapPost("", async (CreateUserRequest request, IUserService service) =>
        {
            var result = await service.CreateAsync(request);
            if (result.Kind != UserResultKind.Success)
            {
                return ToError(result);
            }

            return Results.Created($"/api/users/{Uri.EscapeDataString(result.User!.Id)}",
                new UserMutationDto(result.User, result.Message));
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersCreate)).ValidateApiAntiforgery();

        users.MapPut("/{id}", async (string id, UpdateUserRequest request, IUserService service) =>
        {
            var result = await service.UpdateAsync(id, request);
            return result.Kind == UserResultKind.Success
                ? Results.Ok(new UserMutationDto(result.User!, result.Message))
                : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersUpdate)).ValidateApiAntiforgery();

        users.MapDelete("/{id}", async (string id, ClaimsPrincipal principal, IUserService service) =>
        {
            var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (actorId is null)
            {
                return Results.Unauthorized();
            }

            var result = await service.DeleteAsync(id, actorId);
            return result.Kind == UserResultKind.Success ? Results.NoContent() : ToError(result);
        }).RequireAuthorization(PermissionCodes.Policy(PermissionCodes.UsersDelete)).ValidateApiAntiforgery();

        return endpoints;
    }

    private static IResult ToError(UserResult result) => result.Kind switch
    {
        UserResultKind.Validation => Results.ValidationProblem(result.Errors!),
        UserResultKind.Conflict => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "Conflicto de usuario.",
            detail: result.Message ?? string.Join(" ", result.Errors?.Values.SelectMany(value => value) ?? [])),
        UserResultKind.NotFound => Results.NotFound(),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
    };
}
