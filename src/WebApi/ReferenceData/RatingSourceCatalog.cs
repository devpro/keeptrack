namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single declaration of which rating sources a domain can pick a primary from, and the code default
/// when an admin hasn't chosen one. Only domains with more than one source are worth making selectable;
/// today that's video games (IGDB, IGDB's critic aggregate, Metacritic) and movies/TV (TMDB vs IMDb).
/// Keeping defaults and available options in one place is what lets the enrichment service and the admin
/// endpoints agree without duplicating that knowledge.
/// <para>
/// A source key is not the same thing as a provider: a source stays declared here for as long as any stored
/// value carries it, even after the provider that produced it stops being the domain's default (see
/// <see cref="Rawg"/>).
/// </para>
/// </summary>
public static class RatingSourceCatalog
{
    /// <summary>
    /// RAWG's own 0-5 user score. No longer selectable as a primary (IGDB replaced RAWG as the default video
    /// game provider) but deliberately still declared: <see cref="ScaleOf"/> throws on an unknown source, and
    /// references linked through RAWG keep this value on record and keep rendering it on detail pages.
    /// Dropping it from <see cref="s_sources"/> is what makes <see cref="Resolve"/> ignore a stored
    /// RAWG-era override and fall back to the current default.
    /// </summary>
    public const string Rawg = "rawg";

    /// <summary>Metacritic's 0-100 critic score - republished by RAWG, absent from IGDB entirely.</summary>
    public const string Metacritic = "metacritic";

    /// <summary>IGDB's own 0-100 user score - the video game default (usually present).</summary>
    public const string Igdb = "igdb";

    /// <summary>
    /// IGDB's 0-100 aggregate of external critic scores. A press score like <see cref="Metacritic"/> but
    /// computed by IGDB from its own sources, so it is a separate key and never written under Metacritic's.
    /// </summary>
    public const string IgdbCritic = "igdbcritic";

    /// <summary>TMDB's own 0-10 vote average - the movie/TV default (always present once resolved).</summary>
    public const string Tmdb = "tmdb";

    /// <summary>IMDb's 0-10 aggregate (via OMDb) - same scale as TMDB, occasionally absent for obscure titles.</summary>
    public const string Imdb = "imdb";

    /// <summary>
    /// How long a *fruitless* rating attempt is remembered before it is worth asking the provider again.
    /// Every consumer that stamps an attempt shares this window: the Explore catalogue backfill and the
    /// reference sync's IMDb backfill. Without it, the handful of titles a source genuinely has nothing for
    /// cost a call on every single pass, forever, and the budget they burn is budget the titles that *are*
    /// rated never get - coverage stops advancing. Declared here beside the source keys rather than privately
    /// in whichever service happens to backfill, so the two can't drift apart.
    /// </summary>
    public static readonly TimeSpan RatingReattemptAfter = TimeSpan.FromDays(90);

    // per domain, the selectable source keys; the first is the code default.
    private static readonly IReadOnlyDictionary<ReferenceItemType, IReadOnlyList<string>> s_sources =
        new Dictionary<ReferenceItemType, IReadOnlyList<string>>
        {
            [ReferenceItemType.Movie] = [Tmdb, Imdb],
            [ReferenceItemType.TvShow] = [Tmdb, Imdb],
            [ReferenceItemType.VideoGame] = [Igdb, IgdbCritic, Metacritic]
        };

    // the scale each source's values are expressed on - the domains don't share one, so any rating that
    // travels to a client has to carry its own. Declared here beside the source keys themselves rather than
    // as constants in whichever feature happens to display a rating.
    private static readonly IReadOnlyDictionary<string, double> s_scales = new Dictionary<string, double>
    {
        [Tmdb] = 10,
        [Imdb] = 10,
        [Rawg] = 5,
        [Metacritic] = 100,
        [Igdb] = 100,
        [IgdbCritic] = 100
    };

    /// <summary>Domains whose primary rating source an admin can choose (those with more than one source).</summary>
    public static IReadOnlyList<ReferenceItemType> SelectableDomains => s_sources.Keys.ToList();

    /// <summary>The scale <paramref name="source"/>'s values are expressed on (10 for TMDB/IMDb, 5 for RAWG, 100 for Metacritic/IGDB).</summary>
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
