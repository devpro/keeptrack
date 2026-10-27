using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The table of rating sources: every key a stored value can carry, its scale, and how long a fruitless attempt is remembered.
/// Pure data, shared by everything that reads or renders a rating.
/// <para>
/// A source key is not a provider, and this table is the wider of the two.
/// A key stays declared while any stored value carries it, after its provider stopped being a domain's default (see <see cref="Rawg"/> and <see cref="Metacritic"/>).
/// Which sources a domain offers an admin depends on the deployment, and <see cref="RatingSourceOptions"/> answers it.
/// </para>
/// </summary>
public static class RatingSourceCatalog
{
    /// <summary>
    /// RAWG's 0 to 5 user score.
    /// Not offered while IGDB is the default video game provider, but still declared:
    /// <see cref="ScaleOf"/> throws on an unknown source, and references linked through RAWG keep and render this value.
    /// It becomes selectable again if a deployment returns to RAWG (see <see cref="RatingSourceOptions"/>).
    /// </summary>
    public const string Rawg = "rawg";

    /// <summary>
    /// Metacritic's 0 to 100 critic score, republished by RAWG and absent from IGDB, whose own critic aggregate is <see cref="IgdbCritic"/>.
    /// Offered only while the default provider reports it, as <see cref="RatingSourceOptions"/> decides.
    /// <para>
    /// Offering it regardless fails quietly: <c>MergeProviderRatings</c> keeps a RAWG-era value through an IGDB refresh,
    /// so old games show a rating while every game linked since shows none.
    /// </para>
    /// </summary>
    public const string Metacritic = "metacritic";

    /// <summary>IGDB's 0 to 100 user score, the video game default, usually present.</summary>
    public const string Igdb = "igdb";

    /// <summary>
    /// IGDB's 0 to 100 aggregate of external critic scores.
    /// A press score like <see cref="Metacritic"/>, but computed by IGDB from its own sources, so it has its own key.
    /// </summary>
    public const string IgdbCritic = "igdbcritic";

    /// <summary>TMDB's 0 to 10 vote average, the movie and TV default, present once resolved.</summary>
    public const string Tmdb = "tmdb";

    /// <summary>IMDb's 0 to 10 aggregate through OMDb, on TMDB's scale, sometimes absent for obscure titles.</summary>
    public const string Imdb = "imdb";

    /// <summary>
    /// How long a fruitless rating attempt is remembered before asking the provider again.
    /// The Explore catalogue backfill and the reference sync's IMDb backfill share it, declared here so they cannot drift apart.
    /// Without it, titles a source has nothing for cost a call on every pass, spending the budget rated titles need, and coverage stops advancing.
    /// </summary>
    public static readonly TimeSpan RatingReattemptAfter = TimeSpan.FromDays(90);

    // sources do not share a scale, so a rating sent to a client carries its own
    private static readonly IReadOnlyDictionary<string, double> s_scales = new Dictionary<string, double>
    {
        [Tmdb] = 10,
        [Imdb] = 10,
        [Rawg] = 5,
        [Metacritic] = 100,
        [Igdb] = 100,
        [IgdbCritic] = 100
    };

    /// <summary>The scale of <paramref name="source"/>'s values (10 for TMDB and IMDb, 5 for RAWG, 100 for Metacritic and IGDB).</summary>
    public static double ScaleOf(string source) =>
        s_scales.TryGetValue(source, out var scale)
            ? scale
            : throw new ArgumentOutOfRangeException(nameof(source), $"No scale is declared for the rating source '{source}'.");
}
