namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The declaration table for rating sources: every key any stored value can carry, the scale each is
/// expressed on, and how long a fruitless attempt at one is remembered. Pure data, shared by everything that
/// reads or renders a rating.
/// <para>
/// A source key is not the same thing as a provider, and this table is deliberately the wider of the two: a
/// key stays declared here for as long as any stored value carries it, long after the provider that produced
/// it stopped being a domain's default (see <see cref="Rawg"/> and <see cref="Metacritic"/>). Which of them a
/// domain currently *offers an admin* is a different, deployment-dependent question, answered by
/// <see cref="RatingSourceOptions"/>.
/// </para>
/// </summary>
public static class RatingSourceCatalog
{
    /// <summary>
    /// RAWG's own 0-5 user score. Not offered while IGDB is the default video game provider, but deliberately
    /// still declared: <see cref="ScaleOf"/> throws on an unknown source, and references linked through RAWG
    /// keep this value on record and keep rendering it on detail pages. It becomes selectable again on its own
    /// if a deployment goes back to RAWG - see <see cref="RatingSourceOptions"/>.
    /// </summary>
    public const string Rawg = "rawg";

    /// <summary>
    /// Metacritic's 0-100 critic score - republished by RAWG, absent from IGDB entirely (whose own critic
    /// aggregate is a separate number under <see cref="IgdbCritic"/>). Offered exactly while a provider that
    /// reports it is the default, which is what <see cref="RatingSourceOptions"/> decides.
    /// <para>
    /// Offering it regardless was a slow leak rather than an obvious break: <c>MergeProviderRatings</c> keeps a
    /// RAWG-era metacritic value through an IGDB refresh, so the games linked back then kept showing one while
    /// every game linked or created since - having never been near RAWG - resolved to no rating at all.
    /// </para>
    /// </summary>
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

    /// <summary>The scale <paramref name="source"/>'s values are expressed on (10 for TMDB/IMDb, 5 for RAWG, 100 for Metacritic/IGDB).</summary>
    public static double ScaleOf(string source) =>
        s_scales.TryGetValue(source, out var scale)
            ? scale
            : throw new ArgumentOutOfRangeException(nameof(source), $"No scale is declared for the rating source '{source}'.");
}
