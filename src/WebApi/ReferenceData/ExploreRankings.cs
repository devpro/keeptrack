using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single declaration of how an Explore domain maps onto a provider: which provider discovers for it (and
/// therefore whose number space its ids live in), and which stored orderings its ranked catalogue is built
/// from. Shared by the refresh pass that writes the catalogue and the read path that pages through it, so the
/// two can never disagree about what they're writing and reading.
/// </summary>
public static class ExploreRankings
{
    /// <summary>
    /// Which provider a domain's suggestions - and their <c>ExternalId</c>s and dismissal records - come from.
    /// The *discovery* provider, deliberately distinct from the admin-selected rating source: an IMDb-ranked
    /// movie suggestion is still identified by a TMDB id. Stored on the dismissal rather than inferred, since
    /// TMDB and RAWG ids are both plain integers with nothing but an explicit provider to keep them apart.
    /// </summary>
    public static string DiscoverySource(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => RatingSourceCatalog.Tmdb,
        ExploreItemType.VideoGame => RatingSourceCatalog.Rawg,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    /// <summary>
    /// The stored orderings a domain's catalogue holds.
    /// <para>
    /// Movies and TV have exactly one whatever the rating source is: TMDB publishes a single top-rated list,
    /// and IMDb has no catalogue API at all, so an IMDb-ranked list is TMDB's ordering with IMDb's number
    /// displayed on it - never a second ordering. RAWG does sort natively by each of its own sources, so video
    /// games genuinely need one stored ranking per source.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Rankings(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => [RatingSourceCatalog.Tmdb],
        ExploreItemType.VideoGame => RatingSourceCatalog.AvailableSources(ReferenceItemType.VideoGame),
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    /// <summary>
    /// The ordering to read (or write) for a domain shown with <paramref name="ratingSource"/> - the one
    /// declared in <see cref="Rankings"/> that the source maps onto.
    /// </summary>
    public static string For(ExploreItemType type, string ratingSource)
    {
        var rankings = Rankings(type);
        return rankings.Contains(ratingSource) ? ratingSource : rankings[0];
    }

    /// <summary>Every (domain, ordering) pair the refresh pass maintains - derived, so a new source needs no second list.</summary>
    public static IEnumerable<(ExploreItemType Type, string Ranking)> All =>
        Enum.GetValues<ExploreItemType>().SelectMany(type => Rankings(type).Select(ranking => (type, ranking)));

    /// <summary>
    /// The <see cref="ReferenceItemType"/> an Explore domain corresponds to, so rating-source resolution goes
    /// through the same <see cref="RatingSourceCatalog"/> the rest of the app uses.
    /// </summary>
    public static ReferenceItemType ToReferenceItemType(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => ReferenceItemType.Movie,
        ExploreItemType.TvShow => ReferenceItemType.TvShow,
        ExploreItemType.VideoGame => ReferenceItemType.VideoGame,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };
}
