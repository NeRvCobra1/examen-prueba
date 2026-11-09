namespace ExamenPrueba.Infrastructure.Security;

public sealed class ApplicationRateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    public RateLimitRuleOptions Login { get; set; } = new();
    public RateLimitRuleOptions Registration { get; set; } = new();
    public RateLimitRuleOptions AdministrativeRead { get; set; } = new();
    public RateLimitRuleOptions AdministrativeMutation { get; set; } = new();

    public bool IsValid() =>
        Login.IsValid() && Registration.IsValid() &&
        AdministrativeRead.IsValid() && AdministrativeMutation.IsValid();
}

public sealed class RateLimitRuleOptions
{
    public int PermitLimit { get; set; }
    public int WindowSeconds { get; set; }

    public bool IsValid() => PermitLimit > 0 && WindowSeconds > 0;
}

public static class RateLimitPolicyNames
{
    public const string AdministrativeRead = "administrative-read";
    public const string AdministrativeMutation = "administrative-mutation";
}
