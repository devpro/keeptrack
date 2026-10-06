using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// How an Explore domain maps onto a provider, declared once: which provider discovers for it, and so the space of its ids, which stored orderings build its catalogue, and which rating source its cards can show.
/// Shared by the refresh that writes the catalogue and the read path that pages it, so they always agree.
/// <para>
/// An injected service, since the video game answers come from the default provider, a deployment choice.
/// </para>
/// </summary>
public class ExploreRankings(ReferenceClientRegistry<IVideoGameReferenceClient> videoGameClients)
{
    /// <summary>
    /// The provider a domain's suggestions, their ids and their dismissals come from: the discovery provider, distinct from the selected rating source, so a movie shown with IMDb is still a TMDB id.
    /// It is stored on a dismissal, since provider ids are plain integers, which also keeps a provider change safe: records made under the old one stay attributed to it.
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
    /// Movies and TV have one whatever the source: TMDB publishes a single top-rated list, and IMDb has no catalogue API, so a list shown with IMDb is TMDB's ordering with IMDb's number.
    /// A game provider sorts by each of its scores, so video games get one ranking per supported source.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> Rankings(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => [RatingSourceCatalog.Tmdb],
        ExploreItemType.VideoGame => DefaultVideoGameClient.SupportedRatingSources,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    /// <summary>
    /// The ordering read or written for a domain shown with <paramref name="ratingSource"/>, the one of <see cref="Rankings"/> the source maps onto.
    /// </summary>
    public string For(ExploreItemType type, string ratingSource)
    {
        var rankings = Rankings(type);
        return rankings.Contains(ratingSource) ? ratingSource : rankings[0];
    }

    /// <summary>
    /// The rating source a domain's cards can display, given the admin's selection.
    /// <para>
    /// Usually the selection, IMDb included for movies and TV, which the refresh backfills since TMDB's listing lacks it.
    /// A source the catalogue cannot carry falls back to the ranking's own, or Metacritic selected under IGDB would leave every card without a number.
    /// Detail pages show every rating a reference stores.
    /// </para>
    /// </summary>
    public string DisplaySource(ExploreItemType type, string ratingSource) =>
        DisplayableSources(type).Contains(ratingSource) ? ratingSource : Rankings(type)[0];

    /// <summary>
    /// The name of the website a suggestion's link opens, given the source key it is stored under (see <c>ExploreCatalogueEntryModel.WebUrls</c>).
    /// <para>
    /// For games it is the client's <see cref="IReferenceProviderClient.DisplayName"/>, so a provider is named once.
    /// TMDB and IMDb have no client to ask (IMDb being a website whose numbers come through OMDb), so they are spelled out.
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

    /// <summary>Every (domain, ordering) pair the refresh maintains, derived, so a new source needs no second list.</summary>
    public IEnumerable<(ExploreItemType Type, string Ranking)> All =>
        Enum.GetValues<ExploreItemType>().SelectMany(type => Rankings(type).Select(ranking => (type, ranking)));

    /// <summary>
    /// The <see cref="ReferenceItemType"/> of an Explore domain, so rating sources resolve like everywhere else.
    /// </summary>
    public static ReferenceItemType ToReferenceItemType(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => ReferenceItemType.Movie,
        ExploreItemType.TvShow => ReferenceItemType.TvShow,
        ExploreItemType.VideoGame => ReferenceItemType.VideoGame,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private IVideoGameReferenceClient DefaultVideoGameClient => videoGameClients.Resolve(null);

    // what an entry can hold a value for: the ranking's sources, plus imdb for movies and TV, fetched per entry since TMDB's listing lacks it
    private IReadOnlyList<string> DisplayableSources(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb],
        ExploreItemType.VideoGame => DefaultVideoGameClient.SupportedRatingSources,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };
}
