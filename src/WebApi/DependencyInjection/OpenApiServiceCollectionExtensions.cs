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

        /*
        builder.Services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc(configuration.OpenApiInfo.Version,
            new OpenApiInfo { Title = configuration.OpenApiInfo.Title, Version = configuration.OpenApiInfo.Version });
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
                    },
                    new[] { "readAccess", "writeAccess" }
                }
            });

            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            c.IncludeXmlComments(xmlPath);
        });
         */
    }
}
