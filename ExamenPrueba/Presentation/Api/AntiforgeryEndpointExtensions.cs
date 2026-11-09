using Microsoft.AspNetCore.Antiforgery;

namespace ExamenPrueba.Presentation.Api;

public static class AntiforgeryEndpointExtensions
{
    public static TBuilder ValidateApiAntiforgery<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.AddEndpointFilter(async (context, next) =>
        {
            var antiforgery = context.HttpContext.RequestServices.GetRequiredService<IAntiforgery>();
            try
            {
                await antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status400BadRequest,
                    title: "Token antiforgery inválido o ausente.");
            }

            return await next(context);
        });
        return builder;
    }
}
