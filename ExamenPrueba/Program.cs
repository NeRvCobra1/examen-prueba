using System.Globalization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Application.Roles;
using ExamenPrueba.Application.Users;
using ExamenPrueba.Client.Pages;
using ExamenPrueba.Components;
using ExamenPrueba.Components.Account;
using ExamenPrueba.Data;
using ExamenPrueba.Infrastructure.Security;
using ExamenPrueba.Presentation.Api;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents()
    .AddAuthenticationStateSerialization();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();
builder.Services.AddAuthorization(options =>
{
    foreach (var code in PermissionCodes.All)
    {
        options.AddPolicy(PermissionCodes.Policy(code), policy =>
            policy.RequireAuthenticatedUser().AddRequirements(new PermissionRequirement(code)));
    }
    options.AddPolicy(SecurityPolicies.UserRolesRead, policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(
            new PermissionRequirement(PermissionCodes.UsersRead),
            new PermissionRequirement(PermissionCodes.RolesRead)));
    options.AddPolicy(SecurityPolicies.UserRolesManage, policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(
            new PermissionRequirement(PermissionCodes.UsersUpdate),
            new PermissionRequirement(PermissionCodes.RolesUpdate)));
});
builder.Services.AddScoped<IPermissionService, PermissionService>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IRoleService, RoleService>();
builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");

var publicOriginValue = builder.Configuration["Application:PublicOrigin"];
if (!Uri.TryCreate(publicOriginValue, UriKind.Absolute, out var publicOrigin) ||
    publicOrigin.Scheme != Uri.UriSchemeHttps || publicOrigin.AbsolutePath != "/" ||
    !string.IsNullOrEmpty(publicOrigin.Query) || !string.IsNullOrEmpty(publicOrigin.Fragment))
{
    throw new InvalidOperationException("Application:PublicOrigin debe ser un origen HTTPS sin ruta ni consulta.");
}
builder.Services.AddSingleton(new UserConfirmationOptions(publicOrigin));

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentityCore<ApplicationUser>(IdentityModelOptions.Configure)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }

        return Task.CompletedTask;
    };
    options.Events.OnRedirectToAccessDenied = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
        }
        else
        {
            context.Response.Redirect(context.RedirectUri);
        }

        return Task.CompletedTask;
    };
});

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

var loginLimit = builder.Configuration.GetSection(LoginRateLimitOptions.SectionName).Get<LoginRateLimitOptions>() ?? new();
if (loginLimit.PermitLimit < 1 || loginLimit.WindowSeconds < 1)
{
    throw new InvalidOperationException("RateLimiting:Login requiere PermitLimit y WindowSeconds mayores que cero.");
}

builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        if (HttpMethods.IsPost(context.Request.Method) &&
            string.Equals(context.Request.Path.Value, "/Account/Login", StringComparison.OrdinalIgnoreCase))
        {
            var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            return RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = loginLimit.PermitLimit,
                Window = TimeSpan.FromSeconds(loginLimit.WindowSeconds),
                QueueLimit = 0,
                AutoReplenishment = true
            });
        }

        return RateLimitPartition.GetNoLimiter("unlimited");
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        await context.HttpContext.Response.WriteAsync("Demasiados intentos de inicio de sesión.", cancellationToken);
    };
});

var app = builder.Build();

await RbacInitializer.InitializeAsync(app.Services, app.Configuration, app.Environment);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseWhen(context => !context.Request.Path.StartsWithSegments("/api"), branch =>
    branch.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));
app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(ExamenPrueba.Client._Imports).Assembly);

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();
app.MapSecurityApi();
app.MapUserApi();
app.MapRoleApi();

app.Run();
