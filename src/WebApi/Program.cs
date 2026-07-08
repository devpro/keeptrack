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
// a hosted BackgroundService (e.g. ReferenceSyncBackgroundService) already catches and logs every
// exception it can anticipate, but this is a systemic safety net for whatever it doesn't: by default,
// an unhandled exception escaping a BackgroundService.ExecuteAsync stops the whole host, taking every
// other endpoint down with it - "Ignore" logs it instead and lets the rest of the app keep serving requests.
builder.Services.Configure<Microsoft.Extensions.Hosting.HostOptions>(opts =>
    opts.BackgroundServiceExceptionBehavior = Microsoft.Extensions.Hosting.BackgroundServiceExceptionBehavior.Ignore);
builder.Services.AddSingleton<Keeptrack.Domain.Services.WatchNextService>();
builder.Services.AddSingleton<Keeptrack.Domain.Services.WishlistService>();
builder.Services.AddSingleton<Keeptrack.WebApi.Import.ImportJobStore>();
builder.Services.AddScoped<Keeptrack.WebApi.Import.TvTimeImportService>();
builder.Services.AddSingleton(configuration.TmdbSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.ITmdbClient, Keeptrack.WebApi.ReferenceData.TmdbClient>(client =>
{
    client.BaseAddress = new Uri("https://api.themoviedb.org/3/");
}).AddStandardResilienceHandler();
// which IBookReferenceClient implementation is registered is a deployment-time choice
// (ReferenceData:BookProvider / ReferenceData__BookProvider) - add a case here for each new provider.
switch (configuration.BookReferenceProvider)
{
    case "OpenLibrary":
        builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IBookReferenceClient, Keeptrack.WebApi.ReferenceData.OpenLibraryClient>(client =>
        {
            client.BaseAddress = new Uri("https://openlibrary.org/");
            client.DefaultRequestHeaders.Add("User-Agent", "Keeptrack/1.0 (+https://github.com/devpro/keeptrack)");
        }).AddStandardResilienceHandler();
        break;
    default:
        throw new InvalidOperationException($"Unknown ReferenceData:BookProvider '{configuration.BookReferenceProvider}'. Supported providers: OpenLibrary.");
}
builder.Services.AddSingleton(configuration.RawgSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IRawgClient, Keeptrack.WebApi.ReferenceData.RawgClient>(client =>
{
    client.BaseAddress = new Uri("https://api.rawg.io/api/");
}).AddStandardResilienceHandler();
builder.Services.AddSingleton(configuration.DiscogsSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IDiscogsClient, Keeptrack.WebApi.ReferenceData.DiscogsClient>(client =>
{
    client.BaseAddress = new Uri("https://api.discogs.com/");
    client.DefaultRequestHeaders.Add("User-Agent", "Keeptrack/1.0 (+https://github.com/devpro/keeptrack)");
}).AddStandardResilienceHandler();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ReferenceEnrichmentService>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ReferenceSyncService>();
builder.Services.AddHostedService<Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService>();
builder.Services.AddMongoDbInfrastructure(configuration);
builder.Services.AddOpenApiWithBearerAuth(configuration);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Firebase's own claim names ("user_id", "role", ...) must stay exactly as issued - without this,
        // some claim types (short JWT claim names like "role") get silently renamed to legacy ClaimTypes.*
        // URIs by the token handler's inbound claim mapping, breaking RequireClaim("role", ...) checks
        // that look for the literal type "role".
        options.MapInboundClaims = false;
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
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin"));
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
