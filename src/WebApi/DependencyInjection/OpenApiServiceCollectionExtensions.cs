namespace Keeptrack.WebApi.DependencyInjection;

public static class OpenApiServiceCollectionExtensions
{
    public static void AddOpenApiWithBearerAuth(this IServiceCollection services, AppConfiguration configuration)
    {
        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer((doc, _, _) =>
            {
                doc.Info = configuration.OpenApiInfo;
                doc.Components = new OpenApiComponents();
                doc.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                doc.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer",
                    In = ParameterLocation.Header,
                    Name = "Authorization",
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
                };
                doc.Security ??= new List<OpenApiSecurityRequirement>();
                doc.Security.Add(new OpenApiSecurityRequirement
                {
                    [new OpenApiSecuritySchemeReference("Bearer")] = ["readAccess", "writeAccess"]
                });

                return Task.CompletedTask;
            });
        });
    }
}
