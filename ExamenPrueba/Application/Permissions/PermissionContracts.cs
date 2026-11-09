using System.Text.Json.Serialization;

namespace ExamenPrueba.Application.Permissions;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CreatePermissionRequest(string? Code, string? Name, string? Description);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdatePermissionRequest(string? Name, string? Description);

public sealed record PermissionDto(
    int Id, string Code, string Name, string? Description, bool IsSystem, int RoleCount);

public sealed record PermissionPageDto(
    IReadOnlyList<PermissionDto> Items, int Page, int PageSize, int TotalCount);

public sealed record RolePermissionDto(
    int Id, string Code, string Name, string? Description, bool IsSystem, bool Assigned, bool Locked);

public sealed record RolePermissionsDto(
    string RoleId, string RoleName, bool IsProtected, IReadOnlyList<RolePermissionDto> Permissions);

public enum PermissionManagementResultKind { Success, Validation, Conflict, NotFound }

public sealed record PermissionManagementResult(
    PermissionManagementResultKind Kind,
    PermissionDto? Permission = null,
    RolePermissionsDto? RolePermissions = null,
    IReadOnlyDictionary<string, string[]>? Errors = null,
    string? Message = null);
