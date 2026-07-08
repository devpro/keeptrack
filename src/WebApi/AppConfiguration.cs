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

    public OpenApiInfo OpenApiInfo { get; } = configuration.TryGetSection<OpenApiInfo>("OpenApi");

    public JwtBearerSettings JwtBearerSettings { get; } = configuration.TryGetSection<JwtBearerSettings>("Authentication:JwtBearer");

    public TmdbSettings TmdbSettings { get; } = configuration.TryGetSection<TmdbSettings>("Tmdb");

    public RawgSettings RawgSettings { get; } = configuration.TryGetSection<RawgSettings>("Rawg");

    public DiscogsSettings DiscogsSettings { get; } = configuration.TryGetSection<DiscogsSettings>("Discogs");

    /// <summary>
    /// Selects which <see cref="ReferenceData.IBookReferenceClient"/> implementation <c>Program.cs</c>
    /// registers - see the switch there for supported values. Overridable via the
    /// <c>ReferenceData__BookProvider</c> environment variable, same convention as every other setting.
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
