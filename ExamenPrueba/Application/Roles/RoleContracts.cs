using System.Text.Json.Serialization;

namespace ExamenPrueba.Application.Roles;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CreateRoleRequest(string? Name);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateRoleRequest(string? Name);

public sealed record RoleDto(string Id, string Name, bool IsProtected, int UserCount);

public sealed record RolePageDto(IReadOnlyList<RoleDto> Items, int Page, int PageSize, int TotalCount);

public sealed record UserRoleDto(string Id, string Name, bool IsProtected, bool Assigned);

public sealed record UserRolesDto(string UserId, IReadOnlyList<UserRoleDto> Roles);

public enum RoleResultKind { Success, Validation, Conflict, NotFound }

public sealed record RoleResult(
    RoleResultKind Kind,
    RoleDto? Role = null,
    UserRolesDto? UserRoles = null,
    IReadOnlyDictionary<string, string[]>? Errors = null,
    string? Message = null);
