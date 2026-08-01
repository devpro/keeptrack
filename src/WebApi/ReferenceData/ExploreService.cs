using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The Explore feature: reads a provider's own best-of listing and suggests acclaimed titles the caller doesn't already track and hasn't dismissed.
/// Querying the provider - not the local reference collections, which only hold titles someone already tracks - is what surfaces genuinely new things.
/// Each domain reads its own reference provider (TMDB for movies/TV, RAWG for video games) and ranks by the admin-selected primary rating source for that domain,
/// exactly like the rest of the app.
/// The one wrinkle is movies/TV under IMDb: IMDb has no catalogue/top-rated API at all, so the *list* still comes from TMDB and only the displayed number is enriched per title.
/// Video games need no such exception - RAWG sorts natively on both of its own sources.
/// Lives in WebApi/ReferenceData (not Domain) as it depends on the provider clients; per-domain branching is confined to the small fetcher/lookup helpers.
/// </summary>
public class ExploreService(
    ITmdbClient tmdbClient,
    IOmdbClient omdbClient,
    IRawgClient rawgClient,
    IAppSettingRepository appSettingRepository,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IVideoGameRepository videoGameRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IExploreDismissalRepository dismissalRepository)
{
    /// <summary>
    /// The provider each domain discovers through, and therefore the <c>ExternalIds</c> key its suggestion ids live in.
    /// Deliberately distinct from the *rating* source: an IMDb-ranked movie suggestion is still identified by a TMDB id.
    /// </summary>
    private const string TmdbProviderKey = "tmdb";

    private const string RawgProviderKey = "rawg";

    private const double TmdbRatingScale = 10;

    private const double RawgRatingScale = 5;

    private const double MetacriticRatingScale = 100;

    /// <summary>
    /// How many provider pages to pull through at most while filling a request.
    /// </summary>
    private const int MaxProviderPages = 5;

    /// <summary>
    /// The top-<paramref name="limit"/> provider suggestions for <paramref name="type"/>, excluding titles the owner already tracks or has dismissed.
    /// The rating shown and the ordering follow the admin's primary source for the domain.
    /// </summary>
    public async Task<List<ExploreSuggestionDto>> GetSuggestionsAsync(ExploreItemType type, string ownerId, int limit, CancellationToken cancellationToken = default)
    {
        var source = await ResolveRankingSourceAsync(type);
        var excludedIds = await BuildExcludedExternalIdsAsync(type, ownerId);
        var excludedTitles = await BuildExcludedTitlesAsync(type, ownerId);

        var fetch = TopRatedFetcher(type, source);
        var chosen = new List<ExploreCandidate>();
        for (var page = 1; page <= MaxProviderPages && chosen.Count < limit; page++)
        {
            var candidates = await fetch(page, cancellationToken);
            if (candidates.Count == 0) break; // past the provider's last page

            foreach (var candidate in candidates)
            {
                if (!excludedIds.Add(candidate.ExternalId)) continue; // tracked, dismissed, or a duplicate across pages
                if (excludedTitles.Contains(TitleNormalizer.Normalize(candidate.Title))) continue;
                chosen.Add(candidate);
                if (chosen.Count >= limit) break;
            }
        }

        return source == RatingSourceCatalog.Imdb
            ? await MapWithImdbRatingsAsync(type, chosen, cancellationToken)
            : [.. chosen.Select(ToDto)];
    }

    /// <summary>
    /// Hides a provider title from the owner's Explore list permanently (until undone).
    /// Idempotent.
    /// </summary>
    public Task DismissAsync(ExploreItemType type, string ownerId, string externalId) =>
        dismissalRepository.AddAsync(new ExploreDismissalModel
        {
            OwnerId = ownerId,
            ItemType = type,
            ExternalSource = DiscoverySource(type),
            ExternalId = externalId
        });

    /// <summary>
    /// Undoes a dismissal so the title can be suggested again.
    /// </summary>
    public Task UndismissAsync(ExploreItemType type, string ownerId, string externalId)
    {
        return dismissalRepository.RemoveAsync(ownerId, type, DiscoverySource(type), externalId);
    }

    /// <summary>
    /// The admin-selected primary rating source for the domain - the same setting (and the same resolver) the
    /// rest of the app ranks and displays by. An admin can additionally force movies/TV back onto TMDB so
    /// discovery never pays the per-title OMDb lookup the IMDb path below costs; that flag is only ever read
    /// when IMDb actually won, and it cannot apply to video games (RAWG's two sources don't include IMDb).
    /// </summary>
    private async Task<string> ResolveRankingSourceAsync(ExploreItemType type)
    {
        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var source = RatingSourceCatalog.Resolve(overrides, ToReferenceItemType(type));
        return source == RatingSourceCatalog.Imdb && await appSettingRepository.GetExploreUseTmdbAsync()
            ? RatingSourceCatalog.Tmdb
            : source;
    }

    // Fill in each chosen title's IMDb rating for display (imdb id via TMDB's external_ids, then one OMDb
    // call), bounded to the returned page. The ORDER stays TMDB's top-rated ranking - deliberately not
    // re-sorted by IMDb: IMDb has no top-rated list API, so re-ranking a page by whatever OMDb happened to
    // return (partial when rate-limited, blank with no key) would scramble the list and float low/unrated
    // titles to the top. Task.WhenAll preserves the input (TMDB) order.
    private async Task<List<ExploreSuggestionDto>> MapWithImdbRatingsAsync(ExploreItemType type, List<ExploreCandidate> chosen, CancellationToken cancellationToken)
    {
        var imdbIdFetcher = ImdbIdFetcher(type);
        var mapped = await Task.WhenAll(chosen.Select(async candidate =>
        {
            var imdbId = await imdbIdFetcher(candidate.ExternalId, cancellationToken);
            var rating = string.IsNullOrEmpty(imdbId) ? null : await omdbClient.GetRatingAsync(imdbId, cancellationToken);
            return ToDto(candidate with { Rating = rating?.Value, RatingScale = rating is null ? null : TmdbRatingScale });
        }));

        return [.. mapped];
    }

    // The one place a domain's discovery provider is named: which client answers, and which ExternalIds /
    // dismissal key its ids belong to. <paramref name="source"/> only reaches RAWG, which sorts natively on
    // both of its sources; TMDB has a single top-rated list whatever the ranking source is (see
    // MapWithImdbRatingsAsync).
    private Func<int, CancellationToken, Task<IReadOnlyList<ExploreCandidate>>> TopRatedFetcher(ExploreItemType type, string source) => type switch
    {
        ExploreItemType.Movie => async (page, token) => ToCandidates(await tmdbClient.GetTopRatedMoviesAsync(page, token)),
        ExploreItemType.TvShow => async (page, token) => ToCandidates(await tmdbClient.GetTopRatedTvShowsAsync(page, token)),
        ExploreItemType.VideoGame => async (page, token) => ToCandidates(await rawgClient.GetTopRatedGamesAsync(page, source, token), source),
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static string DiscoverySource(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie or ExploreItemType.TvShow => TmdbProviderKey,
        ExploreItemType.VideoGame => RawgProviderKey,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private Func<string, CancellationToken, Task<string?>> ImdbIdFetcher(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => tmdbClient.GetMovieImdbIdAsync,
        ExploreItemType.TvShow => tmdbClient.GetTvShowImdbIdAsync,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private IExploreSourceRepository SourceRepository(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => movieRepository,
        ExploreItemType.TvShow => tvShowRepository,
        ExploreItemType.VideoGame => videoGameRepository,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    // Provider ids the owner must not be suggested: what they dismissed, plus what they already track. The
    // latter is their linked reference ids resolved to those reference documents' own provider id - bounded
    // by the owner's collection size; the reference docs are the small, shared metadata ones, not tenant rows.
    private async Task<HashSet<string>> BuildExcludedExternalIdsAsync(ExploreItemType type, string ownerId)
    {
        var excluded = new HashSet<string>(await dismissalRepository.FindDismissedExternalIdsAsync(ownerId, type, DiscoverySource(type)));
        excluded.UnionWith(await TrackedExternalIdsAsync(type, await SourceRepository(type).FindLinkedReferenceIdsAsync(ownerId)));
        return excluded;
    }

    // The second half of "don't suggest what they already have": an item the owner typed in or imported may
    // never have been linked to a reference document at all (automatic resolution deliberately gives up when
    // a title search returns several candidates), so it has no provider id to exclude by. Matching normalized
    // titles catches those. Two genuinely different works sharing one title is possible, but hiding one
    // discovery card is a far smaller cost than repeatedly suggesting something the owner already owns.
    private async Task<HashSet<string>> BuildExcludedTitlesAsync(ExploreItemType type, string ownerId) =>
        [.. (await SourceRepository(type).FindDistinctTitlesAsync(ownerId)).Select(TitleNormalizer.Normalize)];

    private async Task<IEnumerable<string>> TrackedExternalIdsAsync(ExploreItemType type, IReadOnlyList<string> referenceIds)
    {
        var provider = DiscoverySource(type);
        return type switch
        {
            ExploreItemType.Movie => ExternalIdsOf(await movieReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            ExploreItemType.TvShow => ExternalIdsOf(await tvShowReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            ExploreItemType.VideoGame => ExternalIdsOf(await videoGameReferenceRepository.FindByIdsAsync(referenceIds), r => r.ExternalIds, provider),
            _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
        };
    }

    private static IEnumerable<string> ExternalIdsOf<TReference>(
        IEnumerable<TReference> references, Func<TReference, IReadOnlyDictionary<string, string>> externalIds, string provider) =>
        references.Select(r => externalIds(r).GetValueOrDefault(provider)).Where(id => !string.IsNullOrEmpty(id)).Select(id => id!);

    private static ReferenceItemType ToReferenceItemType(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => ReferenceItemType.Movie,
        ExploreItemType.TvShow => ReferenceItemType.TvShow,
        ExploreItemType.VideoGame => ReferenceItemType.VideoGame,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static IReadOnlyList<ExploreCandidate> ToCandidates(IReadOnlyList<TmdbTopRatedItem> items)
    {
        return
        [
            .. items.Select(i => new ExploreCandidate(
                i.TmdbId, i.Title, i.Year, i.Synopsis, i.PosterUrl, i.VoteAverage, i.VoteAverage is null ? null : TmdbRatingScale))
        ];
    }

    // RAWG reports both of its scores on every listing entry, so the one the admin selected is picked here
    // with no second request - and its scale travels with it (0-5 for RAWG's own, 0-100 for Metacritic's).
    private static IReadOnlyList<ExploreCandidate> ToCandidates(IReadOnlyList<RawgTopRatedItem> items, string source)
    {
        var metacritic = source == RatingSourceCatalog.Metacritic;
        return
        [
            .. items.Select(i =>
            {
                var rating = metacritic ? i.Metacritic : i.Rating;
                return new ExploreCandidate(
                    i.ExternalId, i.Title, i.Year, null, i.ImageUrl, rating,
                    rating is null ? null : metacritic ? MetacriticRatingScale : RawgRatingScale);
            })
        ];
    }

    private static ExploreSuggestionDto ToDto(ExploreCandidate candidate) => new()
    {
        ExternalId = candidate.ExternalId,
        Title = candidate.Title,
        Year = candidate.Year,
        ImageUrl = candidate.ImageUrl,
        Synopsis = candidate.Synopsis,
        Rating = candidate.Rating,
        RatingScale = candidate.RatingScale
    };

    /// <summary>
    /// One provider suggestion, normalized across providers so the paging/exclusion loop above is written once instead of per domain.
    /// The rating carries its own scale because the domains don't share one.
    /// </summary>
    private sealed record ExploreCandidate(string ExternalId, string Title, int? Year, string? Synopsis, string? ImageUrl, double? Rating, double? RatingScale);
}
