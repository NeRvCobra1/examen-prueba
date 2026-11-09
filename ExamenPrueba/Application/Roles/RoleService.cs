using System.Data;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ExamenPrueba.Application.Roles;

public sealed class RoleService(
    RoleManager<IdentityRole> roleManager,
    UserManager<ApplicationUser> userManager,
    ApplicationDbContext dbContext,
    ILogger<RoleService> logger) : IRoleService
{
    private static readonly SemaphoreSlim AdminRoleMutationLock = new(1, 1);

    public async Task<RolePageDto> ListAsync(
        int page, int pageSize, string? search, CancellationToken cancellationToken)
    {
        var roles = roleManager.Roles.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var normalizedSearch = roleManager.NormalizeKey(search.Trim());
            roles = roles.Where(role =>
                role.NormalizedName != null && role.NormalizedName.Contains(normalizedSearch));
        }

        var totalCount = await roles.CountAsync(cancellationToken);
        var pageRoles = await roles.OrderBy(role => role.NormalizedName).ThenBy(role => role.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        var roleIds = pageRoles.Select(role => role.Id).ToArray();
        var counts = await dbContext.UserRoles.AsNoTracking()
            .Where(userRole => roleIds.Contains(userRole.RoleId))
            .GroupBy(userRole => userRole.RoleId)
            .Select(group => new { RoleId = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.RoleId, item => item.Count, cancellationToken);

        return new RolePageDto(pageRoles.Select(role => ToDto(role, counts.GetValueOrDefault(role.Id))).ToArray(),
            page, pageSize, totalCount);
    }

    public async Task<RoleDto?> GetAsync(string id, CancellationToken cancellationToken)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return null;
        }

        var userCount = await dbContext.UserRoles.AsNoTracking()
            .CountAsync(userRole => userRole.RoleId == id, cancellationToken);
        return ToDto(role, userCount);
    }

    public async Task<RoleResult> CreateAsync(CreateRoleRequest request)
    {
        var validation = ValidateName(request.Name);
        if (validation is not null)
        {
            return Validation(validation);
        }

        var name = request.Name!.Trim();
        if (IsProtectedName(name))
        {
            return Conflict("Admin y User son nombres reservados.");
        }

        var role = new IdentityRole(name);
        try
        {
            var created = await roleManager.CreateAsync(role);
            return created.Succeeded
                ? new RoleResult(RoleResultKind.Success, ToDto(role, 0))
                : FromIdentityErrors(created);
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al crear un rol.");
            return Conflict("No fue posible crear el rol por un conflicto de datos.");
        }
    }

    public async Task<RoleResult> UpdateAsync(string id, UpdateRoleRequest request)
    {
        var validation = ValidateName(request.Name);
        if (validation is not null)
        {
            return Validation(validation);
        }

        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return new RoleResult(RoleResultKind.NotFound);
        }

        if (IsProtected(role))
        {
            return Conflict("Los roles Admin y User no pueden renombrarse.");
        }

        var name = request.Name!.Trim();
        if (IsProtectedName(name))
        {
            return Conflict("Admin y User son nombres reservados.");
        }

        role.Name = name;
        try
        {
            var updated = await roleManager.UpdateAsync(role);
            if (!updated.Succeeded)
            {
                return FromIdentityErrors(updated);
            }

            var count = await dbContext.UserRoles.CountAsync(userRole => userRole.RoleId == id);
            return new RoleResult(RoleResultKind.Success, ToDto(role, count));
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(exception, "Conflicto de concurrencia al renombrar un rol.");
            return Conflict("El rol cambió durante la operación. Actualiza la lista y reintenta.");
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al renombrar un rol.");
            return Conflict("No fue posible renombrar el rol por un conflicto de datos.");
        }
    }

    public async Task<RoleResult> DeleteAsync(string id, CancellationToken cancellationToken)
    {
        var role = await roleManager.FindByIdAsync(id);
        if (role is null)
        {
            return new RoleResult(RoleResultKind.NotFound);
        }

        if (IsProtected(role))
        {
            return Conflict("Los roles Admin y User no pueden eliminarse.");
        }

        await using var transaction = await dbContext.Database.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        if (await dbContext.UserRoles.AnyAsync(userRole => userRole.RoleId == id, cancellationToken))
        {
            return Conflict("El rol todavía está asignado a uno o más usuarios.");
        }

        if (await dbContext.RolePermissions.AnyAsync(rolePermission => rolePermission.RoleId == id, cancellationToken))
        {
            return Conflict("El rol todavía tiene permisos asignados.");
        }

        try
        {
            var deleted = await roleManager.DeleteAsync(role);
            if (!deleted.Succeeded)
            {
                return FromIdentityErrors(deleted, RoleResultKind.Conflict);
            }

            await transaction.CommitAsync(cancellationToken);
            return new RoleResult(RoleResultKind.Success);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(exception, "Conflicto de concurrencia al eliminar un rol.");
            return Conflict("El rol cambió durante la operación. Actualiza la lista y reintenta.");
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto de integridad al eliminar un rol.");
            return Conflict("No fue posible eliminar el rol por un conflicto de integridad.");
        }
    }

    public async Task<RoleResult> GetUserRolesAsync(string userId, CancellationToken cancellationToken)
    {
        if (await userManager.FindByIdAsync(userId) is null)
        {
            return new RoleResult(RoleResultKind.NotFound);
        }

        var assigned = await dbContext.UserRoles.AsNoTracking()
            .Where(userRole => userRole.UserId == userId)
            .Select(userRole => userRole.RoleId)
            .ToHashSetAsync(cancellationToken);
        var roles = await roleManager.Roles.AsNoTracking()
            .OrderBy(role => role.NormalizedName).ThenBy(role => role.Id)
            .ToListAsync(cancellationToken);
        return new RoleResult(RoleResultKind.Success, UserRoles: new UserRolesDto(userId,
            roles.Select(role => new UserRoleDto(
                role.Id, role.Name ?? string.Empty, IsProtected(role), assigned.Contains(role.Id))).ToArray()));
    }

    public async Task<RoleResult> AssignAsync(string userId, string roleId, string actorId)
    {
        var role = await roleManager.FindByIdAsync(roleId);
        if (role is null)
        {
            return new RoleResult(RoleResultKind.NotFound, Message: "El rol no existe.");
        }

        var requiresAdminLock = IsAdmin(role);
        if (requiresAdminLock)
        {
            await AdminRoleMutationLock.WaitAsync();
        }

        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            var user = await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return new RoleResult(RoleResultKind.NotFound, Message: "El usuario no existe.");
            }

            if (requiresAdminLock)
            {
                var adminCheck = await ValidateAdminMutationAsync(actorId, userId, assigning: true);
                if (adminCheck is not null)
                {
                    return adminCheck;
                }
            }

            if (await userManager.IsInRoleAsync(user, role.Name!))
            {
                return Conflict("El usuario ya tiene asignado ese rol.");
            }

            var assigned = await userManager.AddToRoleAsync(user, role.Name!);
            if (!assigned.Succeeded)
            {
                return FromIdentityErrors(assigned, RoleResultKind.Conflict);
            }

            await transaction.CommitAsync();
            return await GetUserRolesAsync(userId, CancellationToken.None);
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al asignar un rol a un usuario.");
            return Conflict("No fue posible asignar el rol por un conflicto de datos.");
        }
        finally
        {
            if (requiresAdminLock)
            {
                AdminRoleMutationLock.Release();
            }
        }
    }

    public async Task<RoleResult> RevokeAsync(
        string userId, string roleId, string actorId, CancellationToken cancellationToken)
    {
        var role = await roleManager.FindByIdAsync(roleId);
        if (role is null)
        {
            return new RoleResult(RoleResultKind.NotFound, Message: "El rol no existe.");
        }

        var requiresAdminLock = IsAdmin(role);
        if (requiresAdminLock)
        {
            await AdminRoleMutationLock.WaitAsync(cancellationToken);
        }

        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var user = await userManager.FindByIdAsync(userId);
            if (user is null)
            {
                return new RoleResult(RoleResultKind.NotFound, Message: "El usuario no existe.");
            }

            if (!await userManager.IsInRoleAsync(user, role.Name!))
            {
                return Conflict("El usuario no tiene asignado ese rol.");
            }

            if (requiresAdminLock)
            {
                var adminCheck = await ValidateAdminMutationAsync(actorId, userId, assigning: false);
                if (adminCheck is not null)
                {
                    return adminCheck;
                }

                var count = await dbContext.UserRoles.CountAsync(
                    userRole => userRole.RoleId == roleId, cancellationToken);
                if (count <= 1)
                {
                    return Conflict("No se puede retirar el rol al último usuario Admin.");
                }
            }

            var revoked = await userManager.RemoveFromRoleAsync(user, role.Name!);
            if (!revoked.Succeeded)
            {
                return FromIdentityErrors(revoked, RoleResultKind.Conflict);
            }

            await transaction.CommitAsync(cancellationToken);
            return await GetUserRolesAsync(userId, cancellationToken);
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al revocar un rol de un usuario.");
            return Conflict("No fue posible revocar el rol por un conflicto de datos.");
        }
        finally
        {
            if (requiresAdminLock)
            {
                AdminRoleMutationLock.Release();
            }
        }
    }

    private async Task<RoleResult?> ValidateAdminMutationAsync(string actorId, string userId, bool assigning)
    {
        var actor = await userManager.FindByIdAsync(actorId);
        if (actor is null || !await userManager.IsInRoleAsync(actor, RoleNames.Admin))
        {
            return new RoleResult(RoleResultKind.Conflict,
                Message: "Los cambios del rol Admin requieren un operador Admin vigente.");
        }

        if (actorId == userId)
        {
            return new RoleResult(RoleResultKind.Conflict, Message: assigning
                ? "No puedes autoasignarte el rol Admin."
                : "No puedes revocarte tu propio rol Admin desde este módulo.");
        }

        return null;
    }

    private RoleDto ToDto(IdentityRole role, int userCount) =>
        new(role.Id, role.Name ?? string.Empty, IsProtected(role), userCount);

    private bool IsProtected(IdentityRole role) => IsProtectedName(role.Name);

    private bool IsAdmin(IdentityRole role) =>
        roleManager.NormalizeKey(role.Name) == roleManager.NormalizeKey(RoleNames.Admin);

    private bool IsProtectedName(string? name)
    {
        var normalized = roleManager.NormalizeKey(name?.Trim());
        return normalized == roleManager.NormalizeKey(RoleNames.Admin) ||
               normalized == roleManager.NormalizeKey(RoleNames.User);
    }

    private static string? ValidateName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "El nombre del rol es obligatorio.";
        }

        var trimmed = name.Trim();
        if (trimmed.Length > 64 || trimmed.Any(character =>
                !char.IsLetterOrDigit(character) && character is not '-' and not '_' and not '.'))
        {
            return "El nombre debe tener hasta 64 caracteres y usar letras, números, punto, guion o guion bajo.";
        }

        return null;
    }

    private static RoleResult Validation(string message) =>
        new(RoleResultKind.Validation,
            Errors: new Dictionary<string, string[]> { ["Name"] = [message] });

    private static RoleResult Conflict(string message) =>
        new(RoleResultKind.Conflict, Message: message);

    private static RoleResult FromIdentityErrors(
        IdentityResult result, RoleResultKind fallback = RoleResultKind.Validation)
    {
        var errors = result.Errors.ToArray();
        var kind = errors.Any(error => error.Code == "DuplicateRoleName")
            ? RoleResultKind.Conflict : fallback;
        return new RoleResult(kind,
            Errors: new Dictionary<string, string[]>
            {
                ["Identity"] = errors.Select(error => error.Description).ToArray()
            },
            Message: kind == RoleResultKind.Conflict
                ? "La operación entra en conflicto con los roles existentes."
                : null);
    }
}
