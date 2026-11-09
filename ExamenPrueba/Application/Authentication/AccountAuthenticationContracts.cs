using System.Text.Json.Serialization;

namespace ExamenPrueba.Application.Authentication;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record PublicRegisterRequest(
    string? Email,
    string? Password,
    string? ConfirmPassword,
    string? ReturnUrl = null);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record AccountLoginRequest(
    string? Email,
    string? Password,
    bool RememberMe = false);

public sealed record AuthenticatedUserDto(
    string Id,
    string? Email,
    IReadOnlyList<string> Roles);

public sealed record PublicRegistrationDto(
    string Id,
    string? Email,
    bool ConfirmationRequired,
    string? Warning);

public enum AccountLoginResultKind
{
    Success,
    Validation,
    Unauthorized,
    RequiresTwoFactor,
    LockedOut
}

public sealed record AccountLoginResult(
    AccountLoginResultKind Kind,
    AuthenticatedUserDto? User = null,
    IReadOnlyDictionary<string, string[]>? Errors = null);
