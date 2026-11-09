using System.Net;
using System.Net.Http.Json;
using ExamenPrueba.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace ExamenPrueba.Tests;

public sealed class AuthApiIntegrationTests
{
    [Fact]
    public async Task JsonAuthenticationUsesConfirmedCookieUserRoleAndAntiforgery()
    {
        using var factory = new TestWebApplicationFactory(useTestAuthentication: false);
        using var client = factory.CreateApiClient();
        var suffix = Guid.NewGuid().ToString("N");
        var email = $"auth-api-{suffix}@example.invalid";
        var password = "Aa9!" + Guid.NewGuid().ToString("N");

        using (var missingCsrf = await client.PostAsJsonAsync("/api/auth/register", new
               {
                   email,
                   password,
                   confirmPassword = password
               }))
        {
            Assert.Equal(HttpStatusCode.BadRequest, missingCsrf.StatusCode);
        }

        var registerToken = await factory.GetPublicAntiforgeryTokenAsync(client);
        using (var register = CreateJsonRequest(HttpMethod.Post, "/api/auth/register", registerToken, new
               {
                   email,
                   password,
                   confirmPassword = password
               }))
        using (var response = await client.SendAsync(register))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        string userId;
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email)
                ?? throw new InvalidOperationException("La API no creó el usuario.");
            userId = user.Id;
            Assert.False(user.EmailConfirmed);
            Assert.Equal(["User"], await userManager.GetRolesAsync(user));
        }

        var unconfirmedToken = await factory.GetPublicAntiforgeryTokenAsync(client);
        using (var login = CreateJsonRequest(HttpMethod.Post, "/api/auth/login", unconfirmedToken, new
               {
                   email,
                   password,
                   rememberMe = false
               }))
        using (var response = await client.SendAsync(login))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByIdAsync(userId)
                ?? throw new InvalidOperationException("El usuario dejó de existir.");
            var confirmationCode = await userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmed = await userManager.ConfirmEmailAsync(user, confirmationCode);
            Assert.True(confirmed.Succeeded);
        }

        var loginToken = await factory.GetPublicAntiforgeryTokenAsync(client);
        using (var login = CreateJsonRequest(HttpMethod.Post, "/api/auth/login", loginToken, new
               {
                   email,
                   password,
                   rememberMe = false
               }))
        using (var response = await client.SendAsync(login))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains(response.Headers, header =>
                string.Equals(header.Key, "Set-Cookie", StringComparison.OrdinalIgnoreCase));
        }

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/admin/overview")).StatusCode);

        using (var logoutWithoutCsrf = await client.PostAsync("/api/auth/logout", content: null))
        {
            Assert.Equal(HttpStatusCode.BadRequest, logoutWithoutCsrf.StatusCode);
        }
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);

        var logoutToken = await factory.GetPublicAntiforgeryTokenAsync(client);
        using (var logout = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout"))
        {
            logout.Headers.Add("X-CSRF-TOKEN", logoutToken);
            using var response = await client.SendAsync(logout);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        }
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);

        var forgedEmail = $"forged-{suffix}@example.invalid";
        var forgedToken = await factory.GetPublicAntiforgeryTokenAsync(client);
        using (var forged = CreateJsonRequest(HttpMethod.Post, "/api/auth/register", forgedToken, new
               {
                   email = forgedEmail,
                   password,
                   confirmPassword = password,
                   role = "Admin"
               }))
        using (var response = await client.SendAsync(forged))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        using (var scope = factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            Assert.Null(await userManager.FindByEmailAsync(forgedEmail));
        }
    }

    private static HttpRequestMessage CreateJsonRequest(
        HttpMethod method, string path, string token, object body)
    {
        var request = new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Add("X-CSRF-TOKEN", token);
        return request;
    }
}
