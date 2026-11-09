namespace ExamenPrueba.Application.Users;

public interface IUserService
{
    Task<UserPageDto> ListAsync(int page, int pageSize, string? search, CancellationToken cancellationToken);
    Task<UserDto?> GetAsync(string id);
    Task<UserResult> CreateAsync(CreateUserRequest request, string? returnUrl = null);
    Task<UserResult> UpdateAsync(string id, UpdateUserRequest request);
    Task<UserResult> DeleteAsync(string id, string actorId);
}
