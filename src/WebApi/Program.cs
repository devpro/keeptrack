// creates the web application builder
var builder = WebApplication.CreateBuilder(args);

// reads the application configuration and configures additional services
var configuration = new AppConfiguration(builder.Configuration);

// adds services to the container
builder.Services.AddControllers(opts => { opts.Filters.Add<ApiExceptionFilterAttribute>(); });
builder.Services.AddOpenApi();
builder.Services.AddAutoMapper(config =>
    {
        config.AllowNullDestinationValues = false;
    },
    typeof(Program).Assembly);
builder.Services.AddHealthChecks();
builder.Services.AddMongoDbInfrastructure(configuration);
builder.Services.AddOpenApiWithBearerAuth(configuration);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = configuration.JwtBearerSettings.Authority;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = configuration.JwtBearerSettings.TokenValidation.Issuer,
            ValidateAudience = true,
            ValidAudience = configuration.JwtBearerSettings.TokenValidation.Audience,
            ValidateLifetime = true
        };
    });
if (configuration.CorsAllowedOrigin.Count != 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy(
            AppConfiguration.CorsPolicyName,
            configurePolicy =>
            {
                configurePolicy
                    .WithOrigins(configuration.CorsAllowedOrigin.ToArray())
                    .AllowAnyHeader()
                    .AllowAnyMethod();
            });
    });
}

// creates the application
var app = builder.Build();

// configures the HTTP request pipeline
if (configuration.IsScalarEnabled)
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options
            .WithTitle(configuration.OpenApiInfo.Title ?? "Keeptrack Web Api")
            .WithTheme(ScalarTheme.Kepler)
            .WithDefaultHttpClient(ScalarTarget.CSharp, ScalarClient.HttpClient);
        options.AddPreferredSecuritySchemes("Bearer");
    });
}
if (configuration.IsHttpsRedirectionEnabled)
{
    app.UseHttpsRedirection();
}
app.UseCors(AppConfiguration.CorsPolicyName);
app.UseExceptionHandler(appBuilder => appBuilder.Run(async ctx =>
{
    ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsJsonAsync(new { error = "An unexpected error occurred." });
}));
app.MapControllers()
    .RequireCors(AppConfiguration.CorsPolicyName);
app.MapHealthChecks(AppConfiguration.HealthCheckEndpoint);

// runs the application
await app.RunAsync();
