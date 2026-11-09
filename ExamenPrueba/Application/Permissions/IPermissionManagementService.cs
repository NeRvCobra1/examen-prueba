namespace ExamenPrueba.Application.Permissions;

public interface IPermissionManagementService
{
    Task<PermissionPageDto> ListAsync(
        int page, int pageSize, string? search, CancellationToken cancellationToken);
    Task<PermissionDto?> GetAsync(int id, CancellationToken cancellationToken);
    Task<PermissionManagementResult> CreateAsync(
        CreatePermissionRequest request, CancellationToken cancellationToken);
    Task<PermissionManagementResult> UpdateAsync(
        int id, UpdatePermissionRequest request, CancellationToken cancellationToken);
    Task<PermissionManagementResult> DeleteAsync(int id, CancellationToken cancellationToken);
    Task<PermissionManagementResult> GetRolePermissionsAsync(
        string roleId, CancellationToken cancellationToken);
    Task<PermissionManagementResult> AssignToRoleAsync(
        string roleId, int permissionId, string actorId, CancellationToken cancellationToken);
    Task<PermissionManagementResult> RevokeFromRoleAsync(
        string roleId, int permissionId, string actorId, CancellationToken cancellationToken);
}
