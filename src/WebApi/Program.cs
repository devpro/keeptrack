var builder = WebApplication.CreateBuilder(args);

var configuration = new AppConfiguration(builder.Configuration);

builder.Services.AddControllers(opts => { opts.Filters.Add<ApiExceptionFilterAttribute>(); });
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks().AddCheck<Keeptrack.WebApi.HealthChecks.MongoDbHealthCheck>("mongodb");
// A background service catches what it can anticipate, and this is the safety net for the rest.
// By default an exception escaping BackgroundService.ExecuteAsync stops the whole host, while "Ignore" logs it and keeps serving requests.
builder.Services.Configure<HostOptions>(opts => opts.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore);
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<BookDto, Keeptrack.Domain.Models.BookModel>, Keeptrack.WebApi.Mappers.BookDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<CarDto, Keeptrack.Domain.Models.CarModel>, Keeptrack.WebApi.Mappers.CarDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<CarHistoryDto, Keeptrack.Domain.Models.CarHistoryModel>, Keeptrack.WebApi.Mappers.CarHistoryDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<CarStationDto, Keeptrack.Domain.Models.CarStationModel>, Keeptrack.WebApi.Mappers.CarStationDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<HouseDto, Keeptrack.Domain.Models.HouseModel>, Keeptrack.WebApi.Mappers.HouseDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<HouseHistoryDto, Keeptrack.Domain.Models.HouseHistoryModel>, Keeptrack.WebApi.Mappers.HouseHistoryDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<HealthProfileDto, Keeptrack.Domain.Models.HealthProfileModel>, Keeptrack.WebApi.Mappers.HealthProfileDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<HealthRecordDto, Keeptrack.Domain.Models.HealthRecordModel>, Keeptrack.WebApi.Mappers.HealthRecordDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<CollectibleDto, Keeptrack.Domain.Models.CollectibleModel>, Keeptrack.WebApi.Mappers.CollectibleDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<GearDto, Keeptrack.Domain.Models.GearModel>, Keeptrack.WebApi.Mappers.GearDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<EpisodeDto, Keeptrack.Domain.Models.EpisodeModel>, Keeptrack.WebApi.Mappers.EpisodeDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<MovieDto, Keeptrack.Domain.Models.MovieModel>, Keeptrack.WebApi.Mappers.MovieDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<AlbumDto, Keeptrack.Domain.Models.AlbumModel>, Keeptrack.WebApi.Mappers.AlbumDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<TvShowDto, Keeptrack.Domain.Models.TvShowModel>, Keeptrack.WebApi.Mappers.TvShowDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<SongDto, Keeptrack.Domain.Models.SongModel>, Keeptrack.WebApi.Mappers.SongDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<PlaylistDto, Keeptrack.Domain.Models.PlaylistModel>, Keeptrack.WebApi.Mappers.PlaylistDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<VideoGameDto, Keeptrack.Domain.Models.VideoGameModel>, Keeptrack.WebApi.Mappers.VideoGameDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.IDtoMapper<UserPreferencesDto, Keeptrack.Domain.Models.UserPreferencesModel>, Keeptrack.WebApi.Mappers.UserPreferencesDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.InProgressShowDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.ShareDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.AmazonOrderPreviewRowDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.GenericVideoGameImportPreviewRowDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.GenericImportPreviewRowDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.CarMetricsDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.HouseMetricsDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.HealthMetricsDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.TvShowReferenceDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.MovieReferenceDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.BookReferenceDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.VideoGameReferenceDtoMapper>();
builder.Services.AddSingleton<Keeptrack.WebApi.Mappers.AlbumReferenceDtoMapper>();
// scoped, since it wraps the scoped IBackgroundJobRepository, and open generic, so it covers every (stage, result) pair
builder.Services.AddScoped(typeof(Keeptrack.WebApi.Jobs.JobStore<,>));
builder.Services.AddScoped<Keeptrack.WebApi.Import.TvTimeImportService>();
builder.Services.AddScoped<Keeptrack.WebApi.Import.CarHistoryImportService>();
builder.Services.AddScoped<Keeptrack.WebApi.Import.HealthImportService>();
builder.Services.AddSingleton(configuration.TmdbSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.ITmdbClient, Keeptrack.WebApi.ReferenceData.TmdbClient>(client =>
{
    client.BaseAddress = new Uri("https://api.themoviedb.org/3/");
    // The resilience handler's TotalRequestTimeout is the real bound on a call,
    // but HttpClient's own 100s Timeout wraps the whole pipeline with its retries and wins whenever it is shorter.
    // Disabling it makes the resilience timeout authoritative (https://github.com/dotnet/extensions/issues/4770).
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
// OMDb supplies IMDb ratings for movies and TV, keyed by the IMDb id TMDB exposes.
// Optional: with no Omdb__ApiKey the client does nothing, and movies and TV keep their TMDB rating alone.
builder.Services.AddSingleton(configuration.OmdbSettings);
// A singleton, the gate of every OMDb call: the daily count lives in MongoDB, shared by replicas,
// while the "allowance spent today" shortcut is process state outliving a request scope.
// It resolves its own scoped repository per operation.
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IOmdbCallBudget, Keeptrack.WebApi.ReferenceData.OmdbCallBudget>();
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IOmdbClient, Keeptrack.WebApi.ReferenceData.OmdbClient>(client =>
{
    client.BaseAddress = new Uri("https://www.omdbapi.com/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
// Every book provider is registered, and an admin picks one per action (see ReferenceClientRegistry),
// ReferenceData:BookProvider only selecting the default for automatic resolution.
// Each is a typed client bridged to the shared interface with AddTransient, since a singleton would pin its handler and defeat IHttpClientFactory's rotation.
// Registration order is the admin picker's order: Google Books first as the default, with the best synopses, covers and catalogue, then Open Library and BnF.
builder.Services.AddSingleton(configuration.GoogleBooksSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.GoogleBooksClient>(client =>
{
    client.BaseAddress = new Uri("https://www.googleapis.com/books/v1/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddBookProviderResilienceHandler();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.GoogleBooksClient>());
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.OpenLibraryClient>(client =>
{
    client.BaseAddress = new Uri("https://openlibrary.org/");
    client.DefaultRequestHeaders.Add("User-Agent", "Keeptrack/1.0 (+https://github.com/devpro/keeptrack)");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddBookProviderResilienceHandler();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.OpenLibraryClient>());
// Open Library also backs the ISBN rating fallback, since Google Books serves no ratings
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookRatingByIsbnLookup>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.OpenLibraryClient>());
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.BnfClient>(client =>
{
    client.BaseAddress = new Uri("https://catalogue.bnf.fr/api/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddBookProviderResilienceHandler();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.BnfClient>());
// a factory, so BookReferenceProvider, computed on access, is read again in every scope
builder.Services.AddScoped(sp => new Keeptrack.WebApi.ReferenceData.ReferenceClientRegistry<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp.GetServices<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(), configuration.BookReferenceProvider));
// Video games are registered like books: every provider, bridged with AddTransient, in the admin picker's order.
// ReferenceData:VideoGameProvider selects the default for automatic resolution, adoption by older references, and Explore's discovery.
// IGDB first as that default, RAWG kept for admin search and its stored ratings, since a refresh only calls the default.
builder.Services.AddSingleton(configuration.IgdbSettings);
// IGDB has no API key: it authenticates with a Twitch app access token, fetched here and attached by IgdbAuthenticationHandler.
// The token client is separate and unauthenticated, being the one call with nothing to authenticate with yet.
builder.Services.AddHttpClient(Keeptrack.WebApi.ReferenceData.IgdbTokenProvider.TokenHttpClientName, client =>
{
    client.BaseAddress = new Uri("https://id.twitch.tv/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IIgdbTokenProvider, Keeptrack.WebApi.ReferenceData.IgdbTokenProvider>();
// singletons hold the token cache and the request budget, since IHttpClientFactory rebuilds the transient handlers on every rotation
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IgdbRateLimiter>();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IgdbAuthenticationHandler>();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IgdbRateLimitHandler>();
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IgdbClient>(client =>
{
    client.BaseAddress = new Uri("https://api.igdb.com/v4/");
    client.Timeout = Timeout.InfiniteTimeSpan;
})
    // The order matters: authentication, then resilience, then rate limiting, outermost first.
    // The rate limiter sits innermost, so its queue wait counts against TotalRequestTimeout rather than waiting forever,
    // and the 429 it returns on a full queue is retried with backoff rather than failing the caller.
    // A retry takes another token, since it is another request against the 4 per second ceiling.
    .AddHttpMessageHandler<Keeptrack.WebApi.ReferenceData.IgdbAuthenticationHandler>()
    .AddProviderResilienceHandler()
    .AddHttpMessageHandler<Keeptrack.WebApi.ReferenceData.IgdbRateLimitHandler>();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IVideoGameReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.IgdbClient>());
builder.Services.AddSingleton(configuration.RawgSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.RawgClient>(client =>
{
    client.BaseAddress = new Uri("https://api.rawg.io/api/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IVideoGameReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.RawgClient>());
builder.Services.AddScoped(sp => new Keeptrack.WebApi.ReferenceData.ReferenceClientRegistry<Keeptrack.WebApi.ReferenceData.IVideoGameReferenceClient>(
    sp.GetServices<Keeptrack.WebApi.ReferenceData.IVideoGameReferenceClient>(), configuration.VideoGameReferenceProvider));
builder.Services.AddSingleton(configuration.DiscogsSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IDiscogsClient, Keeptrack.WebApi.ReferenceData.DiscogsClient>(client =>
{
    client.BaseAddress = new Uri("https://api.discogs.com/");
    client.DefaultRequestHeaders.Add("User-Agent", "Keeptrack/1.0 (+https://github.com/devpro/keeptrack)");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ReferenceEnrichmentService>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ReferenceSyncService>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.TvShowStatusReconciliationService>();
// scoped, since it reads the scoped video game registry to know the discovery provider
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreRankings>();
// scoped for the same reason: the video game sources are those the default provider reports
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.RatingSourceOptions>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreService>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreCatalogueRefreshService>();
builder.Services.AddHostedService<Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService>();
builder.Services.AddMongoDbInfrastructure(configuration);
builder.Services.AddOpenApiWithBearerAuth(configuration);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Firebase's claim names ("user_id", "role") must stay as issued.
        // The inbound claim mapping would rename short names like "role" to legacy ClaimTypes URIs, and RequireClaim("role", ...) would never match.
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
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin"))
    // Members and admins get the whole app, and an account without a role is the free preview tier (see FreeTierQuota).
    // Granted like admin, as a Firebase custom claim role=member (see CONTRIBUTING.md).
    .AddPolicy("MemberOnly", policy => policy.RequireClaim("role", "member", "admin"));
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
app.UseExceptionHandler(appBuilder => appBuilder.Run(async ctx =>
{
    ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
    ctx.Response.ContentType = "application/json";
    await ctx.Response.WriteAsJsonAsync(new { error = "An unexpected error occurred." });
}));
app.MapControllers()
    .RequireCors(AppConfiguration.CorsPolicyName);
app.MapHealthChecks(AppConfiguration.HealthCheckEndpoint);

await app.RunAsync();

namespace Keeptrack.WebApi
{
    public partial class Program { }
}
