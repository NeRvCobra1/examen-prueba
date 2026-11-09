using System.Net;
using System.Net.Http.Json;
using ExamenPrueba.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ExamenPrueba.Tests;

public sealed class RateLimitingIntegrationTests
{
    [Fact]
    public async Task AdministrativePoliciesAreIndependentPerUserAndRecoverAfterWindow()
    {
        using var factory = new TestWebApplicationFactory(
            readLimit: 2, mutationLimit: 1, administrativeWindowSeconds: 3);
        using (var scope = factory.Services.CreateScope())
        {
            var configured = scope.ServiceProvider
                .GetRequiredService<IOptions<ApplicationRateLimitingOptions>>().Value;
            Assert.Equal(2, configured.AdministrativeRead.PermitLimit);
            Assert.Equal(1, configured.AdministrativeMutation.PermitLimit);
            Assert.Equal(3, configured.AdministrativeRead.WindowSeconds);
        }
        var firstAdmin = await factory.CreateUserAsync(admin: true);
        var secondAdmin = await factory.CreateUserAsync(admin: true);
        using var firstClient = factory.CreateApiClient(firstAdmin.Id);
        using var secondClient = factory.CreateApiClient(secondAdmin.Id);

        Assert.Equal(HttpStatusCode.OK, (await firstClient.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await firstClient.GetAsync("/api/roles")).StatusCode);
        using var rejectedRead = await firstClient.GetAsync("/api/permissions");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejectedRead.StatusCode);
        Assert.NotNull(rejectedRead.Headers.RetryAfter?.Delta);
        Assert.Equal(HttpStatusCode.OK, (await secondClient.GetAsync("/api/users")).StatusCode);

        var firstToken = await factory.GetAntiforgeryTokenAsync(firstClient);
        using var firstCreate = CreatePermissionRequest("rate.first", firstToken);
        using var firstCreateResponse = await firstClient.SendAsync(firstCreate);
        Assert.True(firstCreateResponse.StatusCode == HttpStatusCode.Created,
            $"Se esperaba 201 y se recibió {(int)firstCreateResponse.StatusCode}: " +
            await firstCreateResponse.Content.ReadAsStringAsync());
        using var rejectedCreate = CreatePermissionRequest("rate.rejected", firstToken);
        using var rejectedMutation = await firstClient.SendAsync(rejectedCreate);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejectedMutation.StatusCode);
        Assert.NotNull(rejectedMutation.Headers.RetryAfter?.Delta);
        Assert.Equal(0, await factory.CountPermissionsAsync("rate.rejected"));

        var secondToken = await factory.GetAntiforgeryTokenAsync(secondClient);
        using var secondCreate = CreatePermissionRequest("rate.seconduser", secondToken);
        using var secondCreateResponse = await secondClient.SendAsync(secondCreate);
        Assert.Equal(HttpStatusCode.Created, secondCreateResponse.StatusCode);

        await Task.Delay(TimeSpan.FromMilliseconds(3200));
        Assert.Equal(HttpStatusCode.OK, (await firstClient.GetAsync("/api/users")).StatusCode);
        using var recoveredCreate = CreatePermissionRequest("rate.recovered", firstToken);
        using var recoveredResponse = await firstClient.SendAsync(recoveredCreate);
        Assert.Equal(HttpStatusCode.Created, recoveredResponse.StatusCode);
    }

    [Fact]
    public async Task RazorAndJsonAuthenticationShareIndependentIpCountersAndIgnoreForwardedHeaders()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = factory.CreateApiClient();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var path = attempt % 2 == 0 ? "/Account/Login" : "/api/auth/login";
            using var response = await PostEmptyFormAsync(client, path, attempt);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, response.StatusCode);
        }

        using var rejectedLogin = await PostEmptyFormAsync(client, "/api/auth/login", 5);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejectedLogin.StatusCode);
        Assert.NotNull(rejectedLogin.Headers.RetryAfter?.Delta);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            var path = attempt % 2 == 0 ? "/Account/Register" : "/api/auth/register";
            using var response = await PostEmptyFormAsync(client, path, attempt + 10);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, response.StatusCode);
        }

        using var rejectedRegistration = await PostEmptyFormAsync(client, "/api/auth/register", 99);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejectedRegistration.StatusCode);
        Assert.NotNull(rejectedRegistration.Headers.RetryAfter?.Delta);
    }

    private static HttpRequestMessage CreatePermissionRequest(string code, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/permissions")
        {
            Content = JsonContent.Create(new { code, name = code, description = "Prueba de límite" })
        };
        request.Headers.Add("X-CSRF-TOKEN", token);
        return request;
    }

    private static async Task<HttpResponseMessage> PostEmptyFormAsync(
        HttpClient client, string path, int spoofedAddress)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent([])
        };
        request.Headers.Add("X-Forwarded-For", $"203.0.113.{spoofedAddress}");
        return await client.SendAsync(request);
    }
}
