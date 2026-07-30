using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The Explore feature: reads the provider's own top-rated lists (TMDB today) and suggests acclaimed titles
/// the caller doesn't already track and hasn't dismissed. The discovery *list* has to come from TMDB - it's
/// the only movie/TV provider with a top-rated catalogue API (IMDb has none) - but the rating shown and the
/// ordering follow the admin's selected primary source, exactly like the rest of the app: TMDB's own vote by
/// default, or IMDb (via OMDb, keyed by the id TMDB exposes) when that's the chosen source. Querying the
/// provider - not the local reference collection, which only holds titles someone already tracked - is what
/// surfaces genuinely new things to watch. Lives in WebApi/ReferenceData (not Domain) as it depends on the
/// provider clients. Per-domain branching is confined to the small fetcher/lookup helpers.
/// </summary>
public class ExploreService(
    ITmdbClient tmdbClient,
    IOmdbClient omdbClient,
    IAppSettingRepository appSettingRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IExploreDismissalRepository dismissalRepository)
{
    private const string TmdbSourceKey = "tmdb";

    /// <summary>TMDB and IMDb ratings are both on a 0-10 scale.</summary>
    private const double RatingScale = 10;

    /// <summary>How many provider pages to pull through at most while filling a request (each ~20 titles).</summary>
    private const int MaxProviderPages = 5;

    /// <summary>
    /// The top-<paramref name="limit"/> provider suggestions for <paramref name="type"/>, excluding titles the
    /// owner already tracks (matched by TMDB id on their linked references) or dismissed. The rating shown and
    /// the ordering follow the admin's primary source for the domain (TMDB by default, IMDb when selected).
    /// </summary>
    public async Task<List<ExploreSuggestionDto>> GetSuggestionsAsync(ExploreItemType type, string ownerId, int limit, CancellationToken cancellationToken = default)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var source = RatingSourceCatalog.Resolve(overrides, ToReferenceItemType(type));
        // an admin can force Explore onto TMDB (its own free vote average) even when IMDb is the primary
        // rating source, so discovery never pays the per-title OMDb lookup cost.
        if (await appSettingRepository.GetExploreUseTmdbAsync()) source = RatingSourceCatalog.Tmdb;

        var exclude = new HashSet<string>(await dismissalRepository.FindDismissedExternalIdsAsync(ownerId, type));
        exclude.UnionWith(await TrackedExternalIdsAsync(type, ownerId));

        var fetch = TopRatedFetcher(type);
        var chosen = new List<TmdbTopRatedItem>();
        for (var page = 1; page <= MaxProviderPages && chosen.Count < limit; page++)
        {
            var candidates = await fetch(page, cancellationToken);
            if (candidates.Count == 0) break;

            foreach (var candidate in candidates)
            {
                if (!exclude.Add(candidate.TmdbId)) continue; // skip tracked/dismissed and any duplicate across pages
                chosen.Add(candidate);
                if (chosen.Count >= limit) break;
            }
        }

        return source == RatingSourceCatalog.Imdb
            ? await MapWithImdbRatingsAsync(type, chosen, cancellationToken)
            : chosen.Select(c => ToDto(c, c.VoteAverage)).ToList();
    }

    /// <summary>Hides a provider title from the owner's Explore list permanently (until undone). Idempotent.</summary>
    public Task DismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.AddAsync(new ExploreDismissalModel { OwnerId = ownerId, ReferenceType = type, ExternalId = externalId });

    /// <summary>Undoes a dismissal so the title can be suggested again.</summary>
    public Task UndismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.RemoveAsync(ownerId, type, externalId);

    // Fill in each chosen title's IMDb rating for display (imdb id via TMDB's external_ids, then one OMDb
    // call), bounded to the returned page. The ORDER stays TMDB's top-rated ranking - deliberately not
    // re-sorted by IMDb: IMDb has no top-rated list API, so re-ranking a page by whatever OMDb happened to
    // return (partial when rate-limited, blank with no key) would scramble the list and float low/unrated
    // titles to the top. Task.WhenAll preserves the input (TMDB) order.
    private async Task<List<ExploreSuggestionDto>> MapWithImdbRatingsAsync(ExploreItemType type, List<TmdbTopRatedItem> chosen, CancellationToken cancellationToken)
    {
        var imdbIdFetcher = ImdbIdFetcher(type);
        var mapped = await Task.WhenAll(chosen.Select(async candidate =>
        {
            var imdbId = await imdbIdFetcher(candidate.TmdbId, cancellationToken);
            var rating = string.IsNullOrEmpty(imdbId) ? null : await omdbClient.GetRatingAsync(imdbId, cancellationToken);
            return ToDto(candidate, rating?.Value);
        }));

        return [.. mapped];
    }

    private Func<int, CancellationToken, Task<IReadOnlyList<TmdbTopRatedItem>>> TopRatedFetcher(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => tmdbClient.GetTopRatedMoviesAsync,
        ExploreItemType.TvShow => tmdbClient.GetTopRatedTvShowsAsync,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private Func<string, CancellationToken, Task<string?>> ImdbIdFetcher(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => tmdbClient.GetMovieImdbIdAsync,
        ExploreItemType.TvShow => tmdbClient.GetTvShowImdbIdAsync,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    // The set of TMDB ids the owner already tracks: their linked reference ids -> those reference documents'
    // own tmdb external id. Bounded by the owner's collection size; the reference docs are the small, shared
    // metadata ones, not tenant rows.
    private async Task<IEnumerable<string>> TrackedExternalIdsAsync(ExploreItemType type, string ownerId) => type switch
    {
        ExploreItemType.Movie => ExternalIdsOf(await movieReferenceRepository.FindByIdsAsync(await movieRepository.FindLinkedReferenceIdsAsync(ownerId)), r => r.ExternalIds),
        ExploreItemType.TvShow => ExternalIdsOf(await tvShowReferenceRepository.FindByIdsAsync(await tvShowRepository.FindLinkedReferenceIdsAsync(ownerId)), r => r.ExternalIds),
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static IEnumerable<string> ExternalIdsOf<TReference>(IEnumerable<TReference> references, Func<TReference, IReadOnlyDictionary<string, string>> externalIds) =>
        references.Select(r => externalIds(r).GetValueOrDefault(TmdbSourceKey)).Where(id => !string.IsNullOrEmpty(id)).Select(id => id!);

    private static ReferenceItemType ToReferenceItemType(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => ReferenceItemType.Movie,
        ExploreItemType.TvShow => ReferenceItemType.TvShow,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static ExploreSuggestionDto ToDto(TmdbTopRatedItem item, double? rating) => new()
    {
        ExternalId = item.TmdbId,
        Title = item.Title,
        Year = item.Year,
        ImageUrl = item.PosterUrl,
        Synopsis = item.Synopsis,
        Rating = rating,
        RatingScale = rating is null ? null : RatingScale
    };
}
