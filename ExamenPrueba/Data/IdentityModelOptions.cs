using Microsoft.AspNetCore.Identity;

namespace ExamenPrueba.Data;

public static class IdentityModelOptions
{
    public static void Configure(IdentityOptions options)
    {
        options.SignIn.RequireConfirmedAccount = true;
        options.User.RequireUniqueEmail = true;
        options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
    }
}
