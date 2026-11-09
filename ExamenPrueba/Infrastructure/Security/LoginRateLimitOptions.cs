namespace ExamenPrueba.Infrastructure.Security;

public sealed class LoginRateLimitOptions
{
    public const string SectionName = "RateLimiting:Login";

    public int PermitLimit { get; set; } = 5;
    public int WindowSeconds { get; set; } = 60;
}
