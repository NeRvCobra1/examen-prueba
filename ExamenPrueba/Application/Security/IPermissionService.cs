namespace ExamenPrueba.Application.Security;

public interface IPermissionService
{
    Task<IReadOnlyList<string>> GetEffectiveCodesAsync(string userId, CancellationToken cancellationToken = default);
}
