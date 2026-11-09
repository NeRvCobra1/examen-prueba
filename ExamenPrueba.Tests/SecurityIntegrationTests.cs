using System.Net;
using System.Net.Http.Json;
using ExamenPrueba.Application.Security;

namespace ExamenPrueba.Tests;

public sealed class SecurityIntegrationTests
{
    [Fact]
    public void InvalidRateLimitConfigurationStopsStartup()
    {
        using var factory = new TestWebApplicationFactory(readLimit: 0);

        var exception = Assert.ThrowsAny<Exception>(() => _ = factory.Services);

        Assert.Contains("PermitLimit", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdministrativeEndpointsRequireAuthentication()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = factory.CreateApiClient();

        using var response = await client.GetAsync("/api/users");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task CombinedPoliciesAndRevocationsUseCurrentSqliteState()
    {
        using var factory = new TestWebApplicationFactory();
        var user = await factory.CreateUserAsync(permissions: [PermissionCodes.UsersRead]);
        using var client = factory.CreateApiClient(user.Id);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.GetAsync($"/api/users/{user.Id}/roles")).StatusCode);

        await factory.GrantPermissionAsync(user.RoleId, PermissionCodes.RolesRead);
        Assert.Equal(HttpStatusCode.OK,
            (await client.GetAsync($"/api/users/{user.Id}/roles")).StatusCode);

        await factory.RevokePermissionAsync(user.RoleId, PermissionCodes.UsersRead);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/users")).StatusCode);
    }

    [Fact]
    public async Task UnexpectedDtoFieldsAndAdminPermissionRevocationAreRejected()
    {
        using var factory = new TestWebApplicationFactory();
        var admin = await factory.CreateUserAsync(admin: true);
        using var client = factory.CreateApiClient(admin.Id);
        var token = await factory.GetAntiforgeryTokenAsync(client);

        using var invalidRequest = new HttpRequestMessage(HttpMethod.Post, "/api/permissions")
        {
            Content = JsonContent.Create(new
            {
                code = "tests.invalid",
                name = "Inválido",
                description = "No debe persistirse",
                unexpected = "forged"
            })
        };
        invalidRequest.Headers.Add("X-CSRF-TOKEN", token);
        using var invalidResponse = await client.SendAsync(invalidRequest);
        Assert.Equal(HttpStatusCode.BadRequest, invalidResponse.StatusCode);
        Assert.Equal(0, await factory.CountPermissionsAsync("tests.invalid"));

        var protectedRelation = await factory.GetAdminPermissionAsync(PermissionCodes.UsersRead);
        using var revokeRequest = new HttpRequestMessage(HttpMethod.Delete,
            $"/api/roles/{protectedRelation.RoleId}/permissions/{protectedRelation.PermissionId}");
        revokeRequest.Headers.Add("X-CSRF-TOKEN", token);
        using var revokeResponse = await client.SendAsync(revokeRequest);
        Assert.Equal(HttpStatusCode.Conflict, revokeResponse.StatusCode);
        Assert.True(await factory.RolePermissionExistsAsync(
            protectedRelation.RoleId, protectedRelation.PermissionId));
    }
}
