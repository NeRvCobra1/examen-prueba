using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ExamenPrueba.Application.Authentication;
using ExamenPrueba.Application.Security;
using ExamenPrueba.Application.Permissions;
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
    options.AddPolicy(SecurityPolicies.RolePermissionsRead, policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(
            new PermissionRequirement(PermissionCodes.RolesRead),
            new PermissionRequirement(PermissionCodes.PermissionsRead)));
    options.AddPolicy(SecurityPolicies.RolePermissionsManage, policy => policy
        .RequireAuthenticatedUser()
        .AddRequirements(
            new PermissionRequirement(PermissionCodes.RolesUpdate),
            new PermissionRequirement(PermissionCodes.PermissionsUpdate)));
});
builder.Services.AddScoped<IPermissionService, PermissionService>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddScoped<IAccountAuthenticationService, AccountAuthenticationService>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IRoleService, RoleService>();
builder.Services.AddScoped<IPermissionManagementService, PermissionManagementService>();
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

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
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
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
builder.Services.AddApplicationRateLimiting(builder.Configuration);

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
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(ExamenPrueba.Client._Imports).Assembly);

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();
app.MapAuthApi();
app.MapSecurityApi();
app.MapUserApi();
app.MapRoleApi();
app.MapPermissionApi();

app.Run();

public partial class Program;
