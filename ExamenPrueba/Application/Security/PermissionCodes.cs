namespace ExamenPrueba.Application.Security;

public static class PermissionCodes
{
    public const string UsersRead = "users.read";
    public const string UsersCreate = "users.create";
    public const string UsersUpdate = "users.update";
    public const string UsersDelete = "users.delete";
    public const string RolesRead = "roles.read";
    public const string RolesCreate = "roles.create";
    public const string RolesUpdate = "roles.update";
    public const string RolesDelete = "roles.delete";
    public const string PermissionsRead = "permissions.read";
    public const string PermissionsCreate = "permissions.create";
    public const string PermissionsUpdate = "permissions.update";
    public const string PermissionsDelete = "permissions.delete";

    public static IReadOnlyList<string> All { get; } =
    [
        UsersRead, UsersCreate, UsersUpdate, UsersDelete,
        RolesRead, RolesCreate, RolesUpdate, RolesDelete,
        PermissionsRead, PermissionsCreate, PermissionsUpdate, PermissionsDelete
    ];

    public static bool IsSystem(string code) => All.Contains(code, StringComparer.Ordinal);

    public static string Policy(string code) => $"permission:{code}";
}
