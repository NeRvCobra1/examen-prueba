using System.Text.Json.Serialization;

namespace ExamenPrueba.Application.Users;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record CreateUserRequest(string? Email, string? Password, string? ConfirmPassword);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateUserRequest(string? Email);

public sealed record UserDto(string Id, string? Email, bool EmailConfirmed, IReadOnlyList<string> Roles);

public sealed record UserPageDto(IReadOnlyList<UserDto> Items, int Page, int PageSize, int TotalCount);

public sealed record UserMutationDto(UserDto User, string? Warning);

public enum UserResultKind { Success, Validation, Conflict, NotFound }

public sealed record UserResult(
    UserResultKind Kind,
    UserDto? User = null,
    IReadOnlyDictionary<string, string[]>? Errors = null,
    string? Message = null);
