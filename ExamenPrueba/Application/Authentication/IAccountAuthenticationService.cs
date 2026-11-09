using ExamenPrueba.Application.Users;

namespace ExamenPrueba.Application.Authentication;

public interface IAccountAuthenticationService
{
    Task<UserResult> RegisterAsync(PublicRegisterRequest request);
    Task<AccountLoginResult> LoginAsync(AccountLoginRequest request);
    Task LogoutAsync();
}
