using ExamenPrueba.Application.Authentication;
using ExamenPrueba.Application.Users;
using Microsoft.AspNetCore.Antiforgery;

namespace ExamenPrueba.Presentation.Api;

public static class AuthApiEndpoints
{
    public static IEndpointRouteBuilder MapAuthApi(this IEndpointRouteBuilder endpoints)
    {
        var auth = endpoints.MapGroup("/api/auth");

        auth.MapGet("/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var token = antiforgery.GetAndStoreTokens(context).RequestToken;
            return Results.Ok(new AntiforgeryResponse(token));
        }).AllowAnonymous();

        auth.MapPost("/register", async (
            PublicRegisterRequest request,
            IAccountAuthenticationService authenticationService) =>
        {
            var result = await authenticationService.RegisterAsync(request);
            if (result.Kind != UserResultKind.Success)
            {
                return ToRegistrationError(result);
            }

            return Results.Ok(new PublicRegistrationDto(
                result.User!.Id,
                result.User.Email,
                ConfirmationRequired: true,
                result.Message));
        }).AllowAnonymous()
            .ValidateApiAntiforgery();

        auth.MapPost("/login", async (
            AccountLoginRequest request,
            IAccountAuthenticationService authenticationService) =>
        {
            var result = await authenticationService.LoginAsync(request);
            return result.Kind switch
            {
                AccountLoginResultKind.Success => Results.Ok(result.User),
                AccountLoginResultKind.Validation => Results.ValidationProblem(result.Errors!),
                AccountLoginResultKind.RequiresTwoFactor => Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Se requiere autenticación de dos factores.",
                    detail: "Completa el inicio de sesión mediante el flujo interactivo de Identity."),
                AccountLoginResultKind.LockedOut => Results.Problem(
                    statusCode: 423,
                    title: "Cuenta bloqueada."),
                _ => Results.Problem(
                    statusCode: StatusCodes.Status401Unauthorized,
                    title: "Credenciales inválidas o cuenta no confirmada.")
            };
        }).AllowAnonymous()
            .ValidateApiAntiforgery();

        auth.MapPost("/logout", async (IAccountAuthenticationService authenticationService) =>
        {
            await authenticationService.LogoutAsync();
            return Results.NoContent();
        }).RequireAuthorization()
            .ValidateApiAntiforgery();

        return endpoints;
    }

    private static IResult ToRegistrationError(UserResult result) => result.Kind switch
    {
        UserResultKind.Validation => Results.ValidationProblem(result.Errors!),
        UserResultKind.Conflict => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "El correo ya está registrado."),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
    };

    public sealed record AntiforgeryResponse(string? Token);
}
