using Microsoft.AspNetCore.Authorization;

namespace ExamenPrueba.Application.Security;

public sealed record PermissionRequirement(string Code) : IAuthorizationRequirement;
