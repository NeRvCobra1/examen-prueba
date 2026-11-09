using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace ExamenPrueba.Infrastructure.Security;

public static class RateLimitingServiceCollectionExtensions
{
    public static IServiceCollection AddApplicationRateLimiting(
        this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetRequiredSection(ApplicationRateLimitingOptions.SectionName);
        var settings = section.Get<ApplicationRateLimitingOptions>()
            ?? throw new InvalidOperationException("No se encontró la configuración de rate limiting.");
        if (!settings.IsValid())
        {
            throw new InvalidOperationException(
                "Cada política de RateLimiting requiere PermitLimit y WindowSeconds mayores que cero.");
        }

        services.AddOptions<ApplicationRateLimitingOptions>()
            .Bind(section)
            .Validate(options => options.IsValid(),
                "Cada política requiere PermitLimit y WindowSeconds mayores que cero.")
            .ValidateOnStart();

        services.AddRateLimiter(options =>
        {
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                var configured = context.RequestServices
                    .GetRequiredService<IOptions<ApplicationRateLimitingOptions>>().Value;
                if (!HttpMethods.IsPost(context.Request.Method))
                {
                    return RateLimitPartition.GetNoLimiter("public:unlimited");
                }

                if (PathEquals(context, "/Account/Login") ||
                    PathEquals(context, "/api/auth/login"))
                {
                    return CreateIpPartition(context, "login", configured.Login);
                }

                if (PathEquals(context, "/Account/Register") ||
                    PathEquals(context, "/api/auth/register"))
                {
                    return CreateIpPartition(context, "registration", configured.Registration);
                }

                return RateLimitPartition.GetNoLimiter("public:unlimited");
            });

            options.AddPolicy(RateLimitPolicyNames.AdministrativeRead, context =>
            {
                var configured = context.RequestServices
                    .GetRequiredService<IOptions<ApplicationRateLimitingOptions>>().Value;
                return CreateUserPartition(context, RateLimitPolicyNames.AdministrativeRead,
                    configured.AdministrativeRead);
            });
            options.AddPolicy(RateLimitPolicyNames.AdministrativeMutation, context =>
            {
                var configured = context.RequestServices
                    .GetRequiredService<IOptions<ApplicationRateLimitingOptions>>().Value;
                return CreateUserPartition(context, RateLimitPolicyNames.AdministrativeMutation,
                    configured.AdministrativeMutation);
            });

            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = WriteRejectedResponseAsync;
        });

        return services;
    }

    private static bool PathEquals(HttpContext context, string expected) =>
        string.Equals(context.Request.Path.Value, expected, StringComparison.OrdinalIgnoreCase);

    private static RateLimitPartition<string> CreateIpPartition(
        HttpContext context, string policy, RateLimitRuleOptions rule)
    {
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return CreateFixedWindowPartition($"{policy}:ip:{remoteIp}", rule);
    }

    private static RateLimitPartition<string> CreateUserPartition(
        HttpContext context, string policy, RateLimitRuleOptions rule)
    {
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var subject = userId is not null
            ? $"user:{userId}"
            : $"anonymous-ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
        return CreateFixedWindowPartition($"{policy}:{subject}", rule);
    }

    private static RateLimitPartition<string> CreateFixedWindowPartition(
        string partitionKey, RateLimitRuleOptions rule) =>
        RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = rule.PermitLimit,
            Window = TimeSpan.FromSeconds(rule.WindowSeconds),
            QueueLimit = 0,
            AutoReplenishment = true
        });

    private static async ValueTask WriteRejectedResponseAsync(
        OnRejectedContext context, CancellationToken cancellationToken)
    {
        var response = context.HttpContext.Response;
        response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds))
                .ToString(CultureInfo.InvariantCulture);
        }

        if (context.HttpContext.Request.Path.StartsWithSegments("/api"))
        {
            await response.WriteAsJsonAsync(new ProblemDetails
            {
                Status = StatusCodes.Status429TooManyRequests,
                Title = "Demasiadas solicitudes.",
                Detail = "Se alcanzó temporalmente el límite de solicitudes para esta operación."
            }, cancellationToken);
            return;
        }

        response.ContentType = "text/plain; charset=utf-8";
        await response.WriteAsync(
            "Demasiadas solicitudes. Espera antes de volver a intentarlo.", cancellationToken);
    }
}
