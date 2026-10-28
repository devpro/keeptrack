using Keeptrack.WebApi.Authentication;
using Keeptrack.WebApi.ReferenceData;
using Withywoods.Configuration;

namespace Keeptrack.WebApi;

public class AppConfiguration(IConfiguration configuration)
{
    public static string CorsPolicyName => "CorsPolicyName";

    public static string HealthCheckEndpoint => "/healthz";

    public bool IsHttpsRedirectionEnabled => configuration.TryGetSection<bool>("Features:IsHttpsRedirectionEnabled");

    public bool IsScalarEnabled => configuration.TryGetSection<bool>("Features:IsScalarEnabled");

    /// <summary>
    /// Gates <see cref="ReferenceSyncBackgroundService"/>: on by default, off in the integration test host (<c>KestrelWebAppFactory</c>),
    /// which would otherwise call real providers on every start.
    /// </summary>
    public bool IsReferenceSyncEnabled => configuration.TryGetSection<bool>("Features:IsReferenceSyncEnabled");

    /// <summary>
    /// How many items a free preview account may create per free-tier collection (movies, TV shows), see <see cref="Controllers.FreeTierQuota"/>.
    /// A missing or zero setting falls back to the default, so a configuration gap never locks free accounts out.
    /// Static, unlike the rest of this class, so the per-request quota check reads this one value without parsing every other section.
    /// </summary>
    public static int GetFreeTierItemLimit(IConfiguration configuration)
    {
        var limit = configuration.GetValue<int>("Features:FreeTierItemLimit");
        return limit > 0 ? limit : 20;
    }

    public OpenApiInfo OpenApiInfo { get; } = configuration.TryGetSection<OpenApiInfo>("OpenApi");

    public JwtBearerSettings JwtBearerSettings => configuration.TryGetSection<JwtBearerSettings>("Authentication:JwtBearer");

    public TmdbSettings TmdbSettings { get; } = configuration.TryGetSection<TmdbSettings>("Tmdb");

    /// <summary>
    /// OMDb (IMDb ratings) is optional: a missing <c>Omdb</c> section disables it, so this falls back to empty settings rather than a null handed to a client.
    /// </summary>
    public OmdbSettings OmdbSettings { get; } = configuration.TryGetSection<OmdbSettings>("Omdb") ?? new OmdbSettings();

    public RawgSettings RawgSettings { get; } = configuration.TryGetSection<RawgSettings>("Rawg");

    /// <summary>
    /// IGDB, the default video game provider, is optional like OMDb: with no <c>Igdb</c> section the client returns nothing rather than failing (see <see cref="IgdbSettings"/>).
    /// </summary>
    public IgdbSettings IgdbSettings { get; } = configuration.TryGetSection<IgdbSettings>("Igdb") ?? new IgdbSettings();

    public DiscogsSettings DiscogsSettings { get; } = configuration.TryGetSection<DiscogsSettings>("Discogs");

    public GoogleBooksSettings GoogleBooksSettings { get; } = configuration.TryGetSection<GoogleBooksSettings>("GoogleBooks");

    /// <summary>
    /// The book provider (<see cref="ReferenceData.IReferenceProviderClient.ProviderKey"/>) used for automatic resolution
    /// and when an admin picks none (see <see cref="ReferenceData.ReferenceClientRegistry{TClient}"/>).
    /// Every registered provider stays available to an admin whatever this value.
    /// </summary>
    public string BookReferenceProvider => configuration.TryGetSection<string>("ReferenceData:BookProvider");

    /// <summary>
    /// The video game provider used for automatic resolution, for the adoption of its id by older references, and as Explore's discovery provider.
    /// Like <see cref="BookReferenceProvider"/>, every registered provider stays available to an admin.
    /// IGDB when unset.
    /// </summary>
    public string VideoGameReferenceProvider =>
        configuration.TryGetSection<string>("ReferenceData:VideoGameProvider") is { Length: > 0 } provider ? provider : Domain.Services.RatingSourceCatalog.Igdb;

    public string ConnectionString => configuration.TryGetSection<string>("Infrastructure:MongoDB:ConnectionString");

    public string DatabaseName => configuration.TryGetSection<string>("Infrastructure:MongoDB:DatabaseName");

    /// <summary>Origins allowed for cross-origin requests (CORS).</summary>
    public List<string> CorsAllowedOrigin { get; } = configuration.TryGetSection<List<string>>("AllowedOrigins");
}
