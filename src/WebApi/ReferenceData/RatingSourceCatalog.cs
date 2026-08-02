namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single declaration of which rating sources a domain can pick a primary from, and the code default
/// when an admin hasn't chosen one. Only domains with more than one source are worth making selectable;
/// today that's just video games (RAWG vs Metacritic). When movies/TV gain a second source (IMDb, phase 2)
/// they get an entry here and reuse the same admin-selection + recompute mechanism with no other change.
/// Keeping defaults and available options in one place is what lets the enrichment service and the admin
/// endpoints agree without duplicating that knowledge.
/// </summary>
public static class RatingSourceCatalog
{
    /// <summary>RAWG's own 0-5 user score - the safer video-game default (usually present).</summary>
    public const string Rawg = "rawg";

    /// <summary>Metacritic's 0-100 critic score - frequently absent on RAWG for smaller/older games.</summary>
    public const string Metacritic = "metacritic";

    /// <summary>TMDB's own 0-10 vote average - the movie/TV default (always present once resolved).</summary>
    public const string Tmdb = "tmdb";

    /// <summary>IMDb's 0-10 aggregate (via OMDb) - same scale as TMDB, occasionally absent for obscure titles.</summary>
    public const string Imdb = "imdb";

    // per domain, the selectable source keys; the first is the code default.
    private static readonly IReadOnlyDictionary<ReferenceItemType, IReadOnlyList<string>> s_sources =
        new Dictionary<ReferenceItemType, IReadOnlyList<string>>
        {
            [ReferenceItemType.Movie] = [Tmdb, Imdb],
            [ReferenceItemType.TvShow] = [Tmdb, Imdb],
            [ReferenceItemType.VideoGame] = [Rawg, Metacritic]
        };

    // the scale each source's values are expressed on - the domains don't share one, so any rating that
    // travels to a client has to carry its own. Declared here beside the source keys themselves rather than
    // as constants in whichever feature happens to display a rating.
    private static readonly IReadOnlyDictionary<string, double> s_scales = new Dictionary<string, double>
    {
        [Tmdb] = 10,
        [Imdb] = 10,
        [Rawg] = 5,
        [Metacritic] = 100
    };

    /// <summary>Domains whose primary rating source an admin can choose (those with more than one source).</summary>
    public static IReadOnlyList<ReferenceItemType> SelectableDomains => s_sources.Keys.ToList();

    /// <summary>The scale <paramref name="source"/>'s values are expressed on (10 for TMDB/IMDb, 5 for RAWG, 100 for Metacritic).</summary>
    public static double ScaleOf(string source) =>
        s_scales.TryGetValue(source, out var scale)
            ? scale
            : throw new ArgumentOutOfRangeException(nameof(source), $"No scale is declared for the rating source '{source}'.");

    /// <summary>Whether <paramref name="domain"/>'s primary rating source is admin-selectable.</summary>
    public static bool IsSelectable(ReferenceItemType domain) => s_sources.ContainsKey(domain);

    /// <summary>The selectable source keys for <paramref name="domain"/> (empty if not selectable).</summary>
    public static IReadOnlyList<string> AvailableSources(ReferenceItemType domain) =>
        s_sources.TryGetValue(domain, out var sources) ? sources : [];

    /// <summary>The code default source for <paramref name="domain"/> (used when no admin override is set).</summary>
    public static string DefaultSource(ReferenceItemType domain) =>
        AvailableSources(domain).FirstOrDefault()
        ?? throw new ArgumentOutOfRangeException(nameof(domain), $"No rating sources are declared for {domain}.");

    /// <summary>
    /// The effective primary source for <paramref name="domain"/> given the admin's stored overrides: the
    /// stored choice when it still names an available source, otherwise the code default (an override for a
    /// source since removed from the catalog is ignored). The single resolver shared by
    /// <c>ReferenceEnrichmentService.GetPrimaryRatingSourceAsync</c> and the Explore feature.
    /// </summary>
    public static string Resolve(IReadOnlyDictionary<string, string> overrides, ReferenceItemType domain) =>
        overrides.TryGetValue(domain.ToString(), out var stored) && AvailableSources(domain).Contains(stored)
            ? stored
            : DefaultSource(domain);
}
