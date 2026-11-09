namespace ExamenPrueba.Application.Roles;

public interface IRoleService
{
    Task<RolePageDto> ListAsync(int page, int pageSize, string? search, CancellationToken cancellationToken);
    Task<RoleDto?> GetAsync(string id, CancellationToken cancellationToken);
    Task<RoleResult> CreateAsync(CreateRoleRequest request);
    Task<RoleResult> UpdateAsync(string id, UpdateRoleRequest request);
    Task<RoleResult> DeleteAsync(string id, CancellationToken cancellationToken);
    Task<RoleResult> GetUserRolesAsync(string userId, CancellationToken cancellationToken);
    Task<RoleResult> AssignAsync(string userId, string roleId, string actorId);
    Task<RoleResult> RevokeAsync(string userId, string roleId, string actorId, CancellationToken cancellationToken);
}
