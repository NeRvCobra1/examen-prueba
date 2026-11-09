using System.Data;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ExamenPrueba.Application.Permissions;

public sealed class PermissionManagementService(
    ApplicationDbContext dbContext,
    RoleManager<IdentityRole> roleManager,
    UserManager<ApplicationUser> userManager,
    ILogger<PermissionManagementService> logger) : IPermissionManagementService
{
    private static readonly SemaphoreSlim MutationLock = new(1, 1);

    public async Task<PermissionPageDto> ListAsync(
        int page, int pageSize, string? search, CancellationToken cancellationToken)
    {
        var query = dbContext.Permissions.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim().ToLowerInvariant();
            query = query.Where(permission =>
                permission.Code.ToLower().Contains(term) || permission.Name.ToLower().Contains(term));
        }

        var totalCount = await query.CountAsync(cancellationToken);
        var permissions = await query.OrderBy(permission => permission.Code).ThenBy(permission => permission.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(cancellationToken);
        var permissionIds = permissions.Select(permission => permission.Id).ToArray();
        var roleCounts = await dbContext.RolePermissions.AsNoTracking()
            .Where(rolePermission => permissionIds.Contains(rolePermission.PermissionId))
            .GroupBy(rolePermission => rolePermission.PermissionId)
            .Select(group => new { PermissionId = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.PermissionId, item => item.Count, cancellationToken);

        return new PermissionPageDto(
            permissions.Select(permission => ToDto(
                permission, roleCounts.GetValueOrDefault(permission.Id))).ToArray(),
            page, pageSize, totalCount);
    }

    public async Task<PermissionDto?> GetAsync(int id, CancellationToken cancellationToken)
    {
        var permission = await dbContext.Permissions.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (permission is null)
        {
            return null;
        }

        var roleCount = await dbContext.RolePermissions.AsNoTracking()
            .CountAsync(rolePermission => rolePermission.PermissionId == id, cancellationToken);
        return ToDto(permission, roleCount);
    }

    public async Task<PermissionManagementResult> CreateAsync(
        CreatePermissionRequest request, CancellationToken cancellationToken)
    {
        var codeValidation = ValidateCode(request.Code, out var code);
        var nameValidation = ValidateName(request.Name, out var name);
        var descriptionValidation = ValidateDescription(request.Description, out var description);
        var errors = Errors(("Code", codeValidation), ("Name", nameValidation),
            ("Description", descriptionValidation));
        if (errors.Count > 0)
        {
            return Validation(errors);
        }

        if (PermissionCodes.IsSystem(code))
        {
            return Conflict("El código está reservado para un permiso del sistema.");
        }

        await MutationLock.WaitAsync(cancellationToken);
        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            if (await dbContext.Permissions.AnyAsync(
                    permission => permission.Code.ToLower() == code, cancellationToken))
            {
                return Conflict("Ya existe un permiso con ese código.");
            }

            var permission = new Permission { Code = code, Name = name, Description = description };
            dbContext.Permissions.Add(permission);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PermissionManagementResult(
                PermissionManagementResultKind.Success, ToDto(permission, 0));
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al crear un permiso.");
            return Conflict("No fue posible crear el permiso por un conflicto de datos.");
        }
        finally
        {
            MutationLock.Release();
        }
    }

    public async Task<PermissionManagementResult> UpdateAsync(
        int id, UpdatePermissionRequest request, CancellationToken cancellationToken)
    {
        var nameValidation = ValidateName(request.Name, out var name);
        var descriptionValidation = ValidateDescription(request.Description, out var description);
        var errors = Errors(("Name", nameValidation), ("Description", descriptionValidation));
        if (errors.Count > 0)
        {
            return Validation(errors);
        }

        await MutationLock.WaitAsync(cancellationToken);
        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var permission = await dbContext.Permissions.SingleOrDefaultAsync(
                item => item.Id == id, cancellationToken);
            if (permission is null)
            {
                return new PermissionManagementResult(PermissionManagementResultKind.NotFound);
            }

            if (PermissionCodes.IsSystem(permission.Code))
            {
                return Conflict("Los permisos del sistema no pueden modificarse.");
            }

            permission.Name = name;
            permission.Description = description;
            await dbContext.SaveChangesAsync(cancellationToken);
            var roleCount = await dbContext.RolePermissions.CountAsync(
                rolePermission => rolePermission.PermissionId == id, cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PermissionManagementResult(
                PermissionManagementResultKind.Success, ToDto(permission, roleCount));
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(exception, "Conflicto de concurrencia al actualizar un permiso.");
            return Conflict("El permiso cambió durante la operación. Actualiza la lista y reintenta.");
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al actualizar un permiso.");
            return Conflict("No fue posible actualizar el permiso por un conflicto de datos.");
        }
        finally
        {
            MutationLock.Release();
        }
    }

    public async Task<PermissionManagementResult> DeleteAsync(int id, CancellationToken cancellationToken)
    {
        await MutationLock.WaitAsync(cancellationToken);
        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var permission = await dbContext.Permissions.SingleOrDefaultAsync(
                item => item.Id == id, cancellationToken);
            if (permission is null)
            {
                return new PermissionManagementResult(PermissionManagementResultKind.NotFound);
            }

            if (PermissionCodes.IsSystem(permission.Code))
            {
                return Conflict("Los permisos del sistema no pueden eliminarse.");
            }

            if (await dbContext.RolePermissions.AnyAsync(
                    rolePermission => rolePermission.PermissionId == id, cancellationToken))
            {
                return Conflict("El permiso todavía está asignado a uno o más roles.");
            }

            dbContext.Permissions.Remove(permission);
            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return new PermissionManagementResult(PermissionManagementResultKind.Success);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(exception, "Conflicto de concurrencia al eliminar un permiso.");
            return Conflict("El permiso cambió durante la operación. Actualiza la lista y reintenta.");
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto de integridad al eliminar un permiso.");
            return Conflict("No fue posible eliminar el permiso por un conflicto de integridad.");
        }
        finally
        {
            MutationLock.Release();
        }
    }

    public async Task<PermissionManagementResult> GetRolePermissionsAsync(
        string roleId, CancellationToken cancellationToken)
    {
        var role = await roleManager.FindByIdAsync(roleId);
        if (role is null)
        {
            return new PermissionManagementResult(
                PermissionManagementResultKind.NotFound, Message: "El rol no existe.");
        }

        var assignedIds = await dbContext.RolePermissions.AsNoTracking()
            .Where(rolePermission => rolePermission.RoleId == roleId)
            .Select(rolePermission => rolePermission.PermissionId)
            .ToHashSetAsync(cancellationToken);
        var permissions = await dbContext.Permissions.AsNoTracking()
            .OrderBy(permission => permission.Code).ThenBy(permission => permission.Id)
            .ToListAsync(cancellationToken);
        var isAdmin = IsRole(role, RoleNames.Admin);
        var isUser = IsRole(role, RoleNames.User);

        return new PermissionManagementResult(PermissionManagementResultKind.Success,
            RolePermissions: new RolePermissionsDto(
                role.Id,
                role.Name ?? string.Empty,
                isAdmin || isUser,
                permissions.Select(permission =>
                {
                    var assigned = assignedIds.Contains(permission.Id);
                    var isSystem = PermissionCodes.IsSystem(permission.Code);
                    return new RolePermissionDto(
                        permission.Id, permission.Code, permission.Name, permission.Description,
                        isSystem, assigned, isAdmin && isSystem || isUser && isSystem && !assigned);
                }).ToArray()));
    }

    public Task<PermissionManagementResult> AssignToRoleAsync(
        string roleId, int permissionId, string actorId, CancellationToken cancellationToken) =>
        ChangeRolePermissionAsync(roleId, permissionId, actorId, assign: true, cancellationToken);

    public Task<PermissionManagementResult> RevokeFromRoleAsync(
        string roleId, int permissionId, string actorId, CancellationToken cancellationToken) =>
        ChangeRolePermissionAsync(roleId, permissionId, actorId, assign: false, cancellationToken);

    private async Task<PermissionManagementResult> ChangeRolePermissionAsync(
        string roleId, int permissionId, string actorId, bool assign, CancellationToken cancellationToken)
    {
        await MutationLock.WaitAsync(cancellationToken);
        try
        {
            await using var transaction = await dbContext.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var actor = await userManager.FindByIdAsync(actorId);
            if (actor is null || !await userManager.IsInRoleAsync(actor, RoleNames.Admin))
            {
                return Conflict("Los cambios Rol–Permiso requieren un operador Admin vigente.");
            }

            var role = await roleManager.FindByIdAsync(roleId);
            if (role is null)
            {
                return new PermissionManagementResult(
                    PermissionManagementResultKind.NotFound, Message: "El rol no existe.");
            }

            var permission = await dbContext.Permissions.SingleOrDefaultAsync(
                item => item.Id == permissionId, cancellationToken);
            if (permission is null)
            {
                return new PermissionManagementResult(
                    PermissionManagementResultKind.NotFound, Message: "El permiso no existe.");
            }

            var isSystem = PermissionCodes.IsSystem(permission.Code);
            if (assign && IsRole(role, RoleNames.User) && isSystem)
            {
                return Conflict("El rol público User no puede recibir permisos administrativos del sistema.");
            }

            if (!assign && IsRole(role, RoleNames.Admin) && isSystem)
            {
                return Conflict("No se pueden retirar los permisos esenciales del rol Admin.");
            }

            var relation = await dbContext.RolePermissions.SingleOrDefaultAsync(
                item => item.RoleId == roleId && item.PermissionId == permissionId, cancellationToken);
            if (assign && relation is not null)
            {
                return Conflict("El rol ya tiene asignado ese permiso.");
            }

            if (!assign && relation is null)
            {
                return Conflict("El rol no tiene asignado ese permiso.");
            }

            if (assign)
            {
                dbContext.RolePermissions.Add(new RolePermission
                {
                    RoleId = roleId,
                    PermissionId = permissionId
                });
            }
            else
            {
                dbContext.RolePermissions.Remove(relation!);
            }

            await dbContext.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return await GetRolePermissionsAsync(roleId, cancellationToken);
        }
        catch (DbUpdateConcurrencyException exception)
        {
            logger.LogWarning(exception, "Conflicto de concurrencia al cambiar una relación Rol–Permiso.");
            return Conflict("La asignación cambió durante la operación. Actualiza la matriz y reintenta.");
        }
        catch (DbUpdateException exception)
        {
            logger.LogWarning(exception, "Conflicto al cambiar una relación Rol–Permiso.");
            return Conflict("No fue posible cambiar la asignación por un conflicto de datos.");
        }
        finally
        {
            MutationLock.Release();
        }
    }

    private PermissionDto ToDto(Permission permission, int roleCount) =>
        new(permission.Id, permission.Code, permission.Name, permission.Description,
            PermissionCodes.IsSystem(permission.Code), roleCount);

    private bool IsRole(IdentityRole role, string name) =>
        roleManager.NormalizeKey(role.Name) == roleManager.NormalizeKey(name);

    private static string? ValidateCode(string? value, out string normalized)
    {
        normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        var segments = normalized.Split('.');
        if (normalized.Length == 0)
        {
            return "El código es obligatorio.";
        }

        if (normalized.Length > 128 || segments.Length < 2 || segments.Any(segment =>
                segment.Length == 0 || segment[0] is < 'a' or > 'z' ||
                segment.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9'))))
        {
            return "El código debe tener hasta 128 caracteres y usar segmentos en minúsculas separados por punto.";
        }

        return null;
    }

    private static string? ValidateName(string? value, out string normalized)
    {
        normalized = value?.Trim() ?? string.Empty;
        return normalized.Length switch
        {
            0 => "El nombre es obligatorio.",
            > 200 => "El nombre no debe superar 200 caracteres.",
            _ => null
        };
    }

    private static string? ValidateDescription(string? value, out string? normalized)
    {
        normalized = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        return normalized?.Length > 500 ? "La descripción no debe superar 500 caracteres." : null;
    }

    private static Dictionary<string, string[]> Errors(
        params (string Field, string? Message)[] validations) => validations
        .Where(validation => validation.Message is not null)
        .ToDictionary(validation => validation.Field, validation => new[] { validation.Message! });

    private static PermissionManagementResult Validation(IReadOnlyDictionary<string, string[]> errors) =>
        new(PermissionManagementResultKind.Validation, Errors: errors);

    private static PermissionManagementResult Conflict(string message) =>
        new(PermissionManagementResultKind.Conflict, Message: message);
}
