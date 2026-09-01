// creates the web application builder
var builder = WebApplication.CreateBuilder(args);

// reads the application configuration and configures additional services
var configuration = new AppConfiguration(builder.Configuration);

// adds services to the container
builder.Services.AddControllers(opts => { opts.Filters.Add<ApiExceptionFilterAttribute>(); });
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks().AddCheck<Keeptrack.WebApi.HealthChecks.MongoDbHealthCheck>("mongodb");
// a hosted BackgroundService (e.g. ReferenceSyncBackgroundService) already catches and logs every exception it can anticipate,
// but this is a systemic safety net for whatever it doesn't: by default, an unhandled exception escaping a BackgroundService.ExecuteAsync stops the whole host,
// taking every other endpoint down with it - "Ignore" logs it instead and lets the rest of the app keep serving requests.
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
// scoped (not singleton) since it wraps the scoped IBackgroundJobRepository; the open-generic
// registration covers every (stage, result) pair without one line per feature
builder.Services.AddScoped(typeof(Keeptrack.WebApi.Jobs.JobStore<,>));
builder.Services.AddScoped<Keeptrack.WebApi.Import.TvTimeImportService>();
builder.Services.AddScoped<Keeptrack.WebApi.Import.CarHistoryImportService>();
builder.Services.AddScoped<Keeptrack.WebApi.Import.HealthImportService>();
builder.Services.AddSingleton(configuration.TmdbSettings);
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.ITmdbClient, Keeptrack.WebApi.ReferenceData.TmdbClient>(client =>
{
    client.BaseAddress = new Uri("https://api.themoviedb.org/3/");
    // AddStandardResilienceHandler's own TotalRequestTimeout (30s default) is meant to be the real bound on a call -
    // but HttpClient's own Timeout (100s default, never otherwise touched here) wraps the whole pipeline including every retry,
    // and silently wins whenever it's shorter than however long the resilience pipeline actually takes to give up.
    // Disabling it lets the resilience handler's own timeout be authoritative instead of a stuck call hanging for a full 100s -
    // see https://github.com/dotnet/extensions/issues/4770 (confirmed against this exact symptom on Discogs).
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
// OMDb supplies IMDb ratings for movies/TV (keyed by the imdb id TMDB already exposes). Optional: with no
// Omdb__ApiKey the client no-ops (see OmdbClient), so movies/TV stay on their TMDB rating alone.
builder.Services.AddSingleton(configuration.OmdbSettings);
// singleton, and the one gate every OMDb call goes through: the daily count itself lives in MongoDB so all
// replicas share it, but the "today's allowance is gone" shortcut is per-process state that must outlive a
// request scope (see OmdbCallBudget). It resolves its own scoped repository per operation.
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IOmdbCallBudget, Keeptrack.WebApi.ReferenceData.OmdbCallBudget>();
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IOmdbClient, Keeptrack.WebApi.ReferenceData.OmdbClient>(client =>
{
    client.BaseAddress = new Uri("https://www.omdbapi.com/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
// every book provider is registered unconditionally (unlike the single-provider TMDB/RAWG/Discogs clients
// below) - an admin picks which one to search with at request time (see ReferenceClientRegistry),
// ReferenceData:BookProvider only selects the *default* used for automatic/background resolution.
// Each is registered as itself via the typed-client pattern, then bridged to the shared interface with
// AddTransient (not AddSingleton - capturing a typed HttpClient in a singleton would pin its handler
// forever and defeat IHttpClientFactory's rotation) so IEnumerable<IBookReferenceClient> resolves both.
// Registration order is also display/priority order in the admin UI's provider picker (ReferenceClientRegistry.All
// preserves it) - Google Books first since it's the default (best synopsis/cover/language/catalogue
// coverage of the three), Open Library and BnF after as fallbacks.
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
// Open Library also backs the cross-provider ISBN rating fallback (Google Books, the default, serves no ratings).
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookRatingByIsbnLookup>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.OpenLibraryClient>());
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.BnfClient>(client =>
{
    client.BaseAddress = new Uri("https://catalogue.bnf.fr/api/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddBookProviderResilienceHandler();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp => sp.GetRequiredService<Keeptrack.WebApi.ReferenceData.BnfClient>());
// a factory (not a plain AddScoped<ReferenceClientRegistry<IBookReferenceClient>>) so configuration.BookReferenceProvider -
// a plain computed-on-access property, not cached - is read fresh on every scope, same "checked fresh"
// requirement IsReferenceSyncEnabled already has elsewhere, without exposing all of AppConfiguration here.
builder.Services.AddScoped(sp => new Keeptrack.WebApi.ReferenceData.ReferenceClientRegistry<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(sp.GetServices<Keeptrack.WebApi.ReferenceData.IBookReferenceClient>(), configuration.BookReferenceProvider));
// video games are the second multi-provider domain, registered the same way books are (see above): every
// provider unconditionally, bridged to the shared interface with AddTransient, registration order being both
// display order in the admin picker and priority when a reference carries more than one provider's id.
// ReferenceData:VideoGameProvider selects the default used for automatic/background resolution, for adopting
// an id onto references linked before it, and as Explore's discovery provider. IGDB first, since it is that
// default; RAWG stays registered so an admin can still search/link with it and so references linked through it
// keep their stored ratings - background refresh only ever calls the default provider.
builder.Services.AddSingleton(configuration.IgdbSettings);
// IGDB has no api key: it authenticates with a Twitch app access token, fetched here and attached by
// IgdbAuthenticationHandler. The token client is deliberately separate and unauthenticated - it is the one
// call that has nothing to authenticate with yet.
builder.Services.AddHttpClient(Keeptrack.WebApi.ReferenceData.IgdbTokenProvider.TokenHttpClientName, client =>
{
    client.BaseAddress = new Uri("https://id.twitch.tv/");
    client.Timeout = Timeout.InfiniteTimeSpan;
}).AddProviderResilienceHandler();
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IIgdbTokenProvider, Keeptrack.WebApi.ReferenceData.IgdbTokenProvider>();
// singletons holding the token cache and the request budget; the handlers wrapping them are transient because
// IHttpClientFactory rebuilds the handler chain on every rotation (which is exactly why neither piece of state
// may live on a handler).
builder.Services.AddSingleton<Keeptrack.WebApi.ReferenceData.IgdbRateLimiter>();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IgdbAuthenticationHandler>();
builder.Services.AddTransient<Keeptrack.WebApi.ReferenceData.IgdbRateLimitHandler>();
builder.Services.AddHttpClient<Keeptrack.WebApi.ReferenceData.IgdbClient>(client =>
{
    client.BaseAddress = new Uri("https://api.igdb.com/v4/");
    client.Timeout = Timeout.InfiniteTimeSpan;
})
    // handler order is load-bearing, and it is authentication -> resilience -> rate limiting (outermost
    // first). The rate limiter goes *innermost*, inside the resilience handler, for two reasons:
    // its queue wait is then covered by TotalRequestTimeout instead of being an unbounded wait behind an
    // infinite client timeout, and the 429 it synthesizes when the queue is full is retried with backoff by
    // the resilience handler rather than escaping to the caller as a hard failure.
    // A retry also re-acquires a token, which is correct - a retry is another request against the 4/s ceiling.
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
// scoped, not singleton: it reads the video game registry to answer which provider discovers for that domain,
// and that registry is itself scoped so the configured default is re-read per scope.
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreRankings>();
// scoped for the same reason: which rating sources the video game domain offers is whatever its registered
// default provider reports, so it follows ReferenceData:VideoGameProvider rather than a hardcoded list.
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.RatingSourceOptions>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreService>();
builder.Services.AddScoped<Keeptrack.WebApi.ReferenceData.ExploreCatalogueRefreshService>();
builder.Services.AddHostedService<Keeptrack.WebApi.ReferenceData.ReferenceSyncBackgroundService>();
builder.Services.AddMongoDbInfrastructure(configuration);
builder.Services.AddOpenApiWithBearerAuth(configuration);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Firebase's own claim names ("user_id", "role", ...) must stay exactly as issued -
        // without this, some claim types (short JWT claim names like "role") get silently renamed to legacy ClaimTypes.
        // URIs by the token handler's inbound claim mapping, breaking RequireClaim("role", ...) checks that look for the literal type "role".
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
    // members (and admins - a membership must never be *less* than the owner's own account) get the full app.
    // authenticated users without the role are the free preview tier (movies + TV shows, capped - see DataCrudControllerBase).
    // Granted the same way as admin: a Firebase custom claim role=member via the Admin SDK (see CONTRIBUTING.md).
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

namespace Keeptrack.WebApi
{
    public partial class Program { }
}
