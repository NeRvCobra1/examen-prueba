using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;

namespace ExamenPrueba.Application.Users;

public sealed class UserService(
    UserManager<ApplicationUser> userManager,
    RoleManager<IdentityRole> roleManager,
    ApplicationDbContext dbContext,
    IEmailSender<ApplicationUser> emailSender,
    UserConfirmationOptions confirmationOptions,
    ILogger<UserService> logger) : IUserService
{
    private static readonly EmailAddressAttribute EmailValidator = new();

    public async Task<UserPageDto> ListAsync(int page, int pageSize, string? search, CancellationToken cancellationToken)
    {
        var users = userManager.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var normalizedSearch = userManager.NormalizeEmail(search.Trim());
            users = users.Where(user => user.NormalizedEmail != null && user.NormalizedEmail.Contains(normalizedSearch));
        }

        var totalCount = await users.CountAsync(cancellationToken);
        var pageUsers = await users.OrderBy(user => user.NormalizedEmail).ThenBy(user => user.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        var items = new List<UserDto>(pageUsers.Count);
        foreach (var user in pageUsers)
        {
            items.Add(await ToDtoAsync(user));
        }

        return new UserPageDto(items, page, pageSize, totalCount);
    }

    public async Task<UserDto?> GetAsync(string id)
    {
        var user = await userManager.FindByIdAsync(id);
        return user is null ? null : await ToDtoAsync(user);
    }

    public async Task<UserResult> CreateAsync(CreateUserRequest request)
    {
        var emailError = ValidateEmail(request.Email);
        if (emailError is not null)
        {
            return Validation("Email", emailError);
        }

        if (string.IsNullOrEmpty(request.Password))
        {
            return Validation("Password", "La contraseña es obligatoria.");
        }

        if (request.Password != request.ConfirmPassword)
        {
            return Validation("ConfirmPassword", "Las contraseñas no coinciden.");
        }

        var email = request.Email!.Trim();
        if (await EmailExistsAsync(email))
        {
            return Conflict("El correo ya está registrado.");
        }

        var user = new ApplicationUser { UserName = email, Email = email };
        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            var created = await userManager.CreateAsync(user, request.Password);
            if (!created.Succeeded)
            {
                return FromIdentityErrors(created);
            }

            var assigned = await userManager.AddToRoleAsync(user, RoleNames.User);
            if (!assigned.Succeeded)
            {
                logger.LogError("La asignación del rol User falló durante la creación de una cuenta.");
                return FromIdentityErrors(assigned);
            }

            await transaction.CommitAsync();
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto de base de datos al crear un usuario.");
            return Conflict("No fue posible crear el usuario por un conflicto de datos.");
        }

        var warning = await SendConfirmationSafelyAsync(user);
        return new UserResult(UserResultKind.Success, await ToDtoAsync(user), Message: warning);
    }

    public async Task<UserResult> UpdateAsync(string id, UpdateUserRequest request)
    {
        var emailError = ValidateEmail(request.Email);
        if (emailError is not null)
        {
            return Validation("Email", emailError);
        }

        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return new UserResult(UserResultKind.NotFound);
        }

        var email = request.Email!.Trim();
        if (string.Equals(user.Email, email, StringComparison.Ordinal))
        {
            return new UserResult(UserResultKind.Success, await ToDtoAsync(user));
        }

        if (await EmailExistsAsync(email, id))
        {
            return Conflict("El correo ya está registrado.");
        }

        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            var emailChanged = await userManager.SetEmailAsync(user, email);
            if (!emailChanged.Succeeded)
            {
                return FromIdentityErrors(emailChanged);
            }

            var nameChanged = await userManager.SetUserNameAsync(user, email);
            if (!nameChanged.Succeeded)
            {
                return FromIdentityErrors(nameChanged);
            }

            await transaction.CommitAsync();
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto de base de datos al actualizar un usuario.");
            return Conflict("No fue posible actualizar el usuario por un conflicto de datos.");
        }

        var warning = await SendConfirmationSafelyAsync(user);
        return new UserResult(UserResultKind.Success, await ToDtoAsync(user), Message: warning);
    }

    public async Task<UserResult> DeleteAsync(string id, string actorId)
    {
        var user = await userManager.FindByIdAsync(id);
        if (user is null)
        {
            return new UserResult(UserResultKind.NotFound);
        }

        if (id == actorId)
        {
            return Conflict("No puedes eliminar tu propia cuenta desde este panel.");
        }

        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync();
            if (await userManager.IsInRoleAsync(user, RoleNames.Admin))
            {
                var adminRole = await roleManager.FindByNameAsync(RoleNames.Admin);
                if (adminRole is null ||
                    await dbContext.UserRoles.CountAsync(userRole => userRole.RoleId == adminRole.Id) <= 1)
                {
                    return Conflict("No se puede eliminar al último usuario Admin.");
                }
            }

            var deleted = await userManager.DeleteAsync(user);
            if (!deleted.Succeeded)
            {
                return FromIdentityErrors(deleted, UserResultKind.Conflict);
            }

            await transaction.CommitAsync();
            return new UserResult(UserResultKind.Success);
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto de integridad al eliminar un usuario.");
            return Conflict("No fue posible eliminar el usuario por un conflicto de integridad.");
        }
    }

    private async Task<UserDto> ToDtoAsync(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        return new UserDto(user.Id, user.Email, user.EmailConfirmed, roles.Order(StringComparer.Ordinal).ToArray());
    }

    private async Task<bool> EmailExistsAsync(string email, string? exceptId = null)
    {
        var byEmail = await userManager.FindByEmailAsync(email);
        if (byEmail is not null && byEmail.Id != exceptId)
        {
            return true;
        }

        var byName = await userManager.FindByNameAsync(email);
        return byName is not null && byName.Id != exceptId;
    }

    private static string? ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return "El correo es obligatorio.";
        }

        email = email.Trim();
        return email.Length > 256 || !EmailValidator.IsValid(email)
            ? "El correo no tiene un formato válido o supera 256 caracteres."
            : null;
    }

    private async Task<string?> SendConfirmationSafelyAsync(ApplicationUser user)
    {
        try
        {
            var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var link = new Uri(confirmationOptions.PublicOrigin,
                $"Account/ConfirmEmail?userId={Uri.EscapeDataString(user.Id)}&code={Uri.EscapeDataString(code)}");
            await emailSender.SendConfirmationLinkAsync(user, user.Email!, HtmlEncoder.Default.Encode(link.ToString()));
            return null;
        }
        catch (Exception exception)
        {
            logger.LogError("La cuenta se guardó, pero falló el envío de confirmación ({ErrorType}).",
                exception.GetType().Name);
            return "La cuenta se guardó, pero falló el envío de la confirmación. Reintenta desde el flujo de confirmación.";
        }
    }

    private static UserResult Validation(string field, string message) =>
        new(UserResultKind.Validation, Errors: new Dictionary<string, string[]> { [field] = [message] });

    private static UserResult Conflict(string message) => new(UserResultKind.Conflict, Message: message);

    private static UserResult FromIdentityErrors(IdentityResult result, UserResultKind fallback = UserResultKind.Validation)
    {
        var errors = result.Errors.ToArray();
        var kind = errors.Any(error => error.Code is "DuplicateEmail" or "DuplicateUserName")
            ? UserResultKind.Conflict : fallback;
        return new UserResult(kind,
            Errors: new Dictionary<string, string[]> { ["Identity"] = errors.Select(error => error.Description).ToArray() },
            Message: kind == UserResultKind.Conflict ? "La operación entra en conflicto con los datos existentes." : null);
    }
}
