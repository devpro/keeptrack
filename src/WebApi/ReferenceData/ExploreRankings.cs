using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single declaration of how an Explore domain maps onto a provider: which provider discovers for it (and
/// therefore whose number space its ids live in), which stored orderings its ranked catalogue is built from,
/// and which rating source its cards can actually show. Shared by the refresh pass that writes the catalogue
/// and the read path that pages through it, so the two can never disagree about what they're writing and
/// reading.
/// <para>
/// An injected service rather than a static class because the video game answers now come from whichever
/// provider is registered as that domain's default - a deployment-time choice, not a compile-time one.
/// </para>
/// </summary>
public class ExploreRankings(ReferenceClientRegistry<IVideoGameReferenceClient> videoGameClients)
{
    /// <summary>
    /// Which provider a domain's suggestions - and their <c>ExternalId</c>s and dismissal records - come from.
    /// The *discovery* provider, deliberately distinct from the admin-selected rating source: an IMDb-ranked
    /// movie suggestion is still identified by a TMDB id. Stored on the dismissal rather than inferred, since
    /// provider ids are plain integers with nothing but an explicit provider to keep them apart - which is also
    /// what makes changing a domain's provider safe: entries and dismissals recorded under the old one stay
    /// unambiguously attributed to it.
    /// </summary>
    public string DiscoverySource(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => RatingSourceCatalog.Tmdb,
        ExploreItemType.VideoGame => DefaultVideoGameClient.ProviderKey,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    /// <summary>
    /// The stored orderings a domain's catalogue holds.
    /// <para>
    /// Movies and TV have exactly one whatever the rating source is: TMDB publishes a single top-rated list,
    /// and IMDb has no catalogue API at all, so an IMDb-ranked list is TMDB's ordering with IMDb's number
    /// displayed on it - never a second ordering. A video game provider does sort natively by each of its own
    /// scores, so that domain gets one stored ranking per source its provider supports.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> Rankings(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => [RatingSourceCatalog.Tmdb],
        ExploreItemType.VideoGame => DefaultVideoGameClient.SupportedRatingSources,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    /// <summary>
    /// The ordering to read (or write) for a domain shown with <paramref name="ratingSource"/> - the one
    /// declared in <see cref="Rankings"/> that the source maps onto.
    /// </summary>
    public string For(ExploreItemType type, string ratingSource)
    {
        var rankings = Rankings(type);
        return rankings.Contains(ratingSource) ? ratingSource : rankings[0];
    }

    /// <summary>
    /// The rating source a domain's cards can actually display, given the admin's selection.
    /// <para>
    /// Usually the selection itself - including IMDb for movies/TV, whose values are not in TMDB's listing but
    /// are backfilled into the catalogue entry by the refresh pass. A source the catalogue has no way to carry
    /// falls back to the ranking's own: Metacritic selected while a provider that doesn't report it discovers
    /// for the domain would otherwise leave every single card with no number at all, permanently. Detail pages
    /// are unaffected - they show every rating a reference actually stores, Metacritic included.
    /// </para>
    /// </summary>
    public string DisplaySource(ExploreItemType type, string ratingSource) =>
        DisplayableSources(type).Contains(ratingSource) ? ratingSource : Rankings(type)[0];

    /// <summary>
    /// The name of the website a suggestion's "read more" link opens, given the source key that link is stored
    /// under (see <c>ExploreCatalogueEntryModel.WebUrls</c>).
    /// <para>
    /// The video game answer is the registered client's own <see cref="IReferenceProviderClient.DisplayName"/>
    /// rather than a second table, so a provider is never named twice. TMDB and IMDb have no client to ask -
    /// TMDB's domain is single-provider and injected directly, and IMDb is a *website*, not a provider here at
    /// all (its numbers arrive through OMDb) - so those two are spelled out.
    /// </para>
    /// </summary>
    public string SiteName(string sourceKey) =>
        videoGameClients.All.FirstOrDefault(c => c.ProviderKey == sourceKey)?.DisplayName
        ?? sourceKey switch
        {
            RatingSourceCatalog.Tmdb => "TMDB",
            RatingSourceCatalog.Imdb => "IMDb",
            _ => sourceKey
        };

    /// <summary>Every (domain, ordering) pair the refresh pass maintains - derived, so a new source needs no second list.</summary>
    public IEnumerable<(ExploreItemType Type, string Ranking)> All =>
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

    private IVideoGameReferenceClient DefaultVideoGameClient => videoGameClients.Resolve(null);

    // what a catalogue entry can hold a value for: the ranking's own sources, plus imdb for movies/TV, which
    // the refresh pass fetches per entry precisely because TMDB's listing doesn't carry it.
    private IReadOnlyList<string> DisplayableSources(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb],
        ExploreItemType.VideoGame => DefaultVideoGameClient.SupportedRatingSources,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };
}
