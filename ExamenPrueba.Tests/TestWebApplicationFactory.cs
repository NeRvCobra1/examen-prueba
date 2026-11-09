using System.Net.Http.Json;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace ExamenPrueba.Tests;

internal sealed class TestWebApplicationFactory(
    int readLimit = 50,
    int mutationLimit = 50,
    int administrativeWindowSeconds = 2,
    int loginWindowSeconds = 30,
    int registrationWindowSeconds = 30,
    bool useTestAuthentication = true) : WebApplicationFactory<Program>
{
    private readonly string databasePath = Path.Combine(
        Path.GetTempPath(), $"examen-prueba-tests-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureLogging(logging => logging.ClearProviders());
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] =
                    $"DataSource={databasePath};Cache=Shared;Pooling=False",
                ["Application:PublicOrigin"] = "https://localhost",
                ["AdminBootstrap:Enabled"] = "false",
                ["RateLimiting:Login:PermitLimit"] = "5",
                ["RateLimiting:Login:WindowSeconds"] = loginWindowSeconds.ToString(),
                ["RateLimiting:Registration:PermitLimit"] = "3",
                ["RateLimiting:Registration:WindowSeconds"] = registrationWindowSeconds.ToString(),
                ["RateLimiting:AdministrativeRead:PermitLimit"] = readLimit.ToString(),
                ["RateLimiting:AdministrativeRead:WindowSeconds"] = administrativeWindowSeconds.ToString(),
                ["RateLimiting:AdministrativeMutation:PermitLimit"] = mutationLimit.ToString(),
                ["RateLimiting:AdministrativeMutation:WindowSeconds"] = administrativeWindowSeconds.ToString()
            });
        });
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<DbContextOptions<ApplicationDbContext>>();
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite($"DataSource={databasePath};Cache=Shared;Pooling=False"));
            if (useTestAuthentication)
            {
                services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = TestAuthenticationHandler.SchemeName;
                        options.DefaultChallengeScheme = TestAuthenticationHandler.SchemeName;
                        options.DefaultScheme = TestAuthenticationHandler.SchemeName;
                    })
                    .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(
                        TestAuthenticationHandler.SchemeName, _ => { });
            }
        });
    }

    public HttpClient CreateApiClient(string? userId = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost")
        });
        if (userId is not null)
        {
            client.DefaultRequestHeaders.Add(TestAuthenticationHandler.UserHeader, userId);
        }

        return client;
    }

    public async Task<TestUser> CreateUserAsync(bool admin = false, params string[] permissions)
    {
        using var scope = Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var suffix = Guid.NewGuid().ToString("N");
        var user = new ApplicationUser
        {
            UserName = $"test-{suffix}@example.invalid",
            Email = $"test-{suffix}@example.invalid",
            EmailConfirmed = true
        };
        AssertSucceeded(await userManager.CreateAsync(user));

        if (admin)
        {
            AssertSucceeded(await userManager.AddToRoleAsync(user, "Admin"));
            var adminRole = await roleManager.FindByNameAsync("Admin")
                ?? throw new InvalidOperationException("No se inicializó el rol Admin.");
            return new TestUser(user.Id, adminRole.Id);
        }

        var role = new IdentityRole($"TestRole_{suffix}");
        AssertSucceeded(await roleManager.CreateAsync(role));
        AssertSucceeded(await userManager.AddToRoleAsync(user, role.Name!));
        var permissionEntities = await dbContext.Permissions
            .Where(permission => permissions.Contains(permission.Code))
            .ToListAsync();
        if (permissionEntities.Count != permissions.Distinct(StringComparer.Ordinal).Count())
        {
            throw new InvalidOperationException("La prueba solicitó un permiso inexistente.");
        }

        dbContext.RolePermissions.AddRange(permissionEntities.Select(permission => new RolePermission
        {
            RoleId = role.Id,
            PermissionId = permission.Id
        }));
        await dbContext.SaveChangesAsync();
        return new TestUser(user.Id, role.Id);
    }

    public async Task GrantPermissionAsync(string roleId, string code)
    {
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var permissionId = await dbContext.Permissions
            .Where(permission => permission.Code == code)
            .Select(permission => permission.Id)
            .SingleAsync();
        dbContext.RolePermissions.Add(new RolePermission { RoleId = roleId, PermissionId = permissionId });
        await dbContext.SaveChangesAsync();
    }

    public async Task RevokePermissionAsync(string roleId, string code)
    {
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var relation = await dbContext.RolePermissions.SingleAsync(rolePermission =>
            rolePermission.RoleId == roleId && rolePermission.Permission.Code == code);
        dbContext.RolePermissions.Remove(relation);
        await dbContext.SaveChangesAsync();
    }

    public async Task<string> GetAntiforgeryTokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/security/antiforgery");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<AntiforgeryResponse>();
        return payload?.Token ?? throw new InvalidOperationException("No se recibió token antiforgery.");
    }

    public async Task<string> GetPublicAntiforgeryTokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/auth/antiforgery");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<AntiforgeryResponse>();
        return payload?.Token ?? throw new InvalidOperationException("No se recibió token antiforgery público.");
    }

    public async Task<int> CountPermissionsAsync(params string[] codes)
    {
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await dbContext.Permissions.CountAsync(permission => codes.Contains(permission.Code));
    }

    public async Task<(string RoleId, int PermissionId)> GetAdminPermissionAsync(string code)
    {
        using var scope = Services.CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var admin = await roleManager.FindByNameAsync("Admin")
            ?? throw new InvalidOperationException("No se inicializó el rol Admin.");
        var permissionId = await dbContext.Permissions
            .Where(permission => permission.Code == code)
            .Select(permission => permission.Id)
            .SingleAsync();
        return (admin.Id, permissionId);
    }

    public async Task<bool> RolePermissionExistsAsync(string roleId, int permissionId)
    {
        using var scope = Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        return await dbContext.RolePermissions.AnyAsync(relation =>
            relation.RoleId == roleId && relation.PermissionId == permissionId);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing)
        {
            return;
        }

        foreach (var suffix in new[] { "", "-shm", "-wal" })
        {
            File.Delete(databasePath + suffix);
        }
    }

    private static void AssertSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(string.Join(", ", result.Errors.Select(error => error.Code)));
        }
    }

    private sealed record AntiforgeryResponse(string Token);
}

internal sealed record TestUser(string Id, string RoleId);
