namespace ExamenPrueba.Data;

public sealed class RolePermission
{
    public required string RoleId { get; set; }
    public int PermissionId { get; set; }
    public Permission Permission { get; set; } = null!;
}
