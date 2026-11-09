using ExamenPrueba.Application.Security;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ExamenPrueba.Infrastructure.Security;

public static class RbacInitializer
{
    public static async Task InitializeAsync(IServiceProvider services, IConfiguration configuration, IHostEnvironment environment)
    {
        using var scope = services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        await dbContext.Database.MigrateAsync();

        foreach (var roleName in new[] { RoleNames.Admin, RoleNames.User })
        {
            if (await roleManager.RoleExistsAsync(roleName))
            {
                continue;
            }

            EnsureSucceeded(await roleManager.CreateAsync(new IdentityRole(roleName)), $"crear el rol {roleName}");
        }

        var existingCodes = await dbContext.Permissions
            .Select(permission => permission.Code)
            .ToListAsync();
        var missingPermissions = PermissionCodes.All
            .Where(code => !existingCodes.Contains(code, StringComparer.Ordinal))
            .Select(code => new Permission { Code = code, Name = code });
        dbContext.Permissions.AddRange(missingPermissions);
        await dbContext.SaveChangesAsync();

        var adminRole = await roleManager.FindByNameAsync(RoleNames.Admin)
            ?? throw new InvalidOperationException("No se encontró el rol Admin después de inicializarlo.");
        var permissionIds = await dbContext.Permissions
            .Where(permission => PermissionCodes.All.Contains(permission.Code))
            .Select(permission => permission.Id)
            .ToListAsync();
        var assignedIds = await dbContext.RolePermissions
            .Where(rolePermission => rolePermission.RoleId == adminRole.Id)
            .Select(rolePermission => rolePermission.PermissionId)
            .ToListAsync();

        dbContext.RolePermissions.AddRange(permissionIds
            .Where(id => !assignedIds.Contains(id))
            .Select(id => new RolePermission { RoleId = adminRole.Id, PermissionId = id }));
        await dbContext.SaveChangesAsync();

        await BootstrapAdminAsync(scope.ServiceProvider, configuration, environment);
    }

    private static async Task BootstrapAdminAsync(
        IServiceProvider services, IConfiguration configuration, IHostEnvironment environment)
    {
        if (!environment.IsDevelopment() || !configuration.GetValue<bool>("AdminBootstrap:Enabled"))
        {
            return;
        }

        var email = configuration["AdminBootstrap:Email"];
        var password = configuration["AdminBootstrap:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("AdminBootstrap requiere Email y Password cuando está habilitado.");
        }

        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var existingUser = await userManager.FindByEmailAsync(email);
        if (existingUser is not null)
        {
            if (!await userManager.IsInRoleAsync(existingUser, RoleNames.Admin))
            {
                throw new InvalidOperationException("AdminBootstrap no eleva una cuenta existente que no es Admin.");
            }

            return;
        }

        var dbContext = services.GetRequiredService<ApplicationDbContext>();
        await using var transaction = await dbContext.Database.BeginTransactionAsync();
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true
        };
        EnsureSucceeded(await userManager.CreateAsync(user, password), "crear la cuenta Admin de Development");
        EnsureSucceeded(await userManager.AddToRoleAsync(user, RoleNames.Admin), "asignar el rol Admin");
        await transaction.CommitAsync();
    }

    private static void EnsureSucceeded(IdentityResult result, string action)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"No fue posible {action}: {string.Join(", ", result.Errors.Select(error => error.Code))}");
        }
    }
}
