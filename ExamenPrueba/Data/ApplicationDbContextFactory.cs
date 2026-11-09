using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Options;

namespace ExamenPrueba.Data;

public sealed class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    private static readonly IServiceProvider DesignTimeServices = CreateDesignTimeServices();

    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection")
            ?? "DataSource=Data/app.db;Cache=Shared";
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(connectionString)
            .UseApplicationServiceProvider(DesignTimeServices)
            .Options;
        return new ApplicationDbContext(options);
    }

    private static IServiceProvider CreateDesignTimeServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.Configure<IdentityOptions>(IdentityModelOptions.Configure);
        return services.BuildServiceProvider();
    }
}
