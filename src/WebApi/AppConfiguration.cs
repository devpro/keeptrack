using Keeptrack.WebApi.Authentication;
using Keeptrack.WebApi.ReferenceData;
using Withywoods.Configuration;

namespace Keeptrack.WebApi;

public class AppConfiguration(IConfiguration configuration)
{
    public static string CorsPolicyName => "CorsPolicyName";

    public static string HealthCheckEndpoint => "/health";

    public bool IsHttpsRedirectionEnabled => configuration.TryGetSection<bool>("Features:IsHttpsRedirectionEnabled");

    public bool IsScalarEnabled => configuration.TryGetSection<bool>("Features:IsScalarEnabled");

    /// <summary>
    /// Gates <see cref="ReferenceSyncBackgroundService"/> - on by default (production wants this running),
    /// but off in the integration test host (see <c>KestrelWebAppFactory</c>), which otherwise fires real
    /// TMDB calls against shared test data on every host start-up.
    /// </summary>
    public bool IsReferenceSyncEnabled => configuration.TryGetSection<bool>("Features:IsReferenceSyncEnabled");

    /// <summary>
    /// How many items a non-member ("free preview") account may create per free-tier collection
    /// (movies, TV shows) - see <see cref="Controllers.DataCrudControllerBase{TDto,TModel}"/>'s quota
    /// check. Guarded against a missing/zero setting so a configuration gap can never lock free
    /// accounts out of creating anything at all. Static (unlike the rest of this class) because the
    /// per-request quota check reads just this one value and must not pay for - or depend on - this
    /// class's eager parsing of every other section.
    /// </summary>
    public static int GetFreeTierItemLimit(IConfiguration configuration)
    {
        var limit = configuration.GetValue<int>("Features:FreeTierItemLimit");
        return limit > 0 ? limit : 20;
    }

    public OpenApiInfo OpenApiInfo { get; } = configuration.TryGetSection<OpenApiInfo>("OpenApi");

    public JwtBearerSettings JwtBearerSettings { get; } = configuration.TryGetSection<JwtBearerSettings>("Authentication:JwtBearer");

    public TmdbSettings TmdbSettings { get; } = configuration.TryGetSection<TmdbSettings>("Tmdb");

    public RawgSettings RawgSettings { get; } = configuration.TryGetSection<RawgSettings>("Rawg");

    public DiscogsSettings DiscogsSettings { get; } = configuration.TryGetSection<DiscogsSettings>("Discogs");

    public GoogleBooksSettings GoogleBooksSettings { get; } = configuration.TryGetSection<GoogleBooksSettings>("GoogleBooks");

    /// <summary>
    /// Which book provider (<see cref="ReferenceData.IBookReferenceClient.ProviderKey"/>) is used for
    /// automatic/background resolution when an admin doesn't pick one explicitly - see
    /// <see cref="ReferenceData.BookReferenceClientRegistry"/>. Every registered provider stays available
    /// to pick from regardless of this value. Overridable via the <c>ReferenceData__BookProvider</c>
    /// environment variable, same convention as every other setting.
    /// </summary>
    public string BookReferenceProvider => configuration.TryGetSection<string>("ReferenceData:BookProvider");

    public string ConnectionString => configuration.TryGetSection<string>("Infrastructure:MongoDB:ConnectionString");

    public string DatabaseName => configuration.TryGetSection<string>("Infrastructure:MongoDB:DatabaseName");

    /// <summary>
    /// Allowed Origin URL for Cross-Origin Requests (CORS)
    /// </summary>
    /// <remarks>
    /// See https://docs.microsoft.com/en-us/aspnet/core/security/cors
    /// </remarks>
    public List<string> CorsAllowedOrigin { get; } = configuration.TryGetSection<List<string>>("AllowedOrigins");
}
