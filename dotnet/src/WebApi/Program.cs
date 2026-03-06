// creates the web application builder and adds services to the container

using Withywoods.AutoMapper.MongoDb;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers(opts => { opts.Filters.Add<CustomExceptionFilterAttribute>(); });
builder.Services.AddOpenApi();
builder.Services.AddAutoMapper(config =>
    {
        // config.CreateMap<ObjectId, string>().ConvertUsing<ObjectIdToStringConverter>();
        // config.CreateMap<string, ObjectId>().ConvertUsing<StringToObjectIdConverter>();
        config.AllowNullDestinationValues = false;
    },
    typeof(Program).Assembly);
builder.Services.AddHealthChecks();

// reads the application configuration and configures additional services
var configuration = new AppConfiguration(builder.Configuration);

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

// creates the application and configures the HTTP request pipeline
var app = builder.Build();

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
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers()
    .RequireCors(AppConfiguration.CorsPolicyName);
app.MapHealthChecks(AppConfiguration.HealthCheckEndpoint);

// runs the application
await app.RunAsync();
