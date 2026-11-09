using System.ComponentModel.DataAnnotations;
using ExamenPrueba.Application.Users;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;

namespace ExamenPrueba.Application.Authentication;

public sealed class AccountAuthenticationService(
    IUserService userService,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    ILogger<AccountAuthenticationService> logger) : IAccountAuthenticationService
{
    private static readonly EmailAddressAttribute EmailValidator = new();

    public Task<UserResult> RegisterAsync(PublicRegisterRequest request) =>
        userService.CreateAsync(
            new CreateUserRequest(request.Email, request.Password, request.ConfirmPassword),
            NormalizeReturnUrl(request.ReturnUrl));

    public async Task<AccountLoginResult> LoginAsync(AccountLoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            request.Email.Length > 256 ||
            !EmailValidator.IsValid(request.Email))
        {
            return Validation("Email", "El correo no tiene un formato válido.");
        }

        if (string.IsNullOrEmpty(request.Password))
        {
            return Validation("Password", "La contraseña es obligatoria.");
        }

        var email = request.Email.Trim();
        var result = await signInManager.PasswordSignInAsync(
            email, request.Password, request.RememberMe, lockoutOnFailure: false);

        if (result.RequiresTwoFactor)
        {
            return new AccountLoginResult(AccountLoginResultKind.RequiresTwoFactor);
        }

        if (result.IsLockedOut)
        {
            return new AccountLoginResult(AccountLoginResultKind.LockedOut);
        }

        if (!result.Succeeded)
        {
            return new AccountLoginResult(AccountLoginResultKind.Unauthorized);
        }

        var user = await userManager.FindByEmailAsync(email);
        if (user is null)
        {
            await signInManager.SignOutAsync();
            logger.LogError("Identity inició una sesión para una cuenta que no pudo volver a cargarse.");
            return new AccountLoginResult(AccountLoginResultKind.Unauthorized);
        }

        var roles = await userManager.GetRolesAsync(user);
        logger.LogInformation("El usuario {UserId} inició sesión.", user.Id);
        return new AccountLoginResult(
            AccountLoginResultKind.Success,
            new AuthenticatedUserDto(
                user.Id,
                user.Email,
                roles.Order(StringComparer.Ordinal).ToArray()));
    }

    public Task LogoutAsync() => signInManager.SignOutAsync();

    private static AccountLoginResult Validation(string field, string message) =>
        new(AccountLoginResultKind.Validation,
            Errors: new Dictionary<string, string[]> { [field] = [message] });

    private static string? NormalizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return null;
        }

        return returnUrl.StartsWith("/", StringComparison.Ordinal) &&
               !returnUrl.StartsWith("//", StringComparison.Ordinal) &&
               !Uri.TryCreate(returnUrl, UriKind.Absolute, out _)
            ? returnUrl
            : null;
    }
}
