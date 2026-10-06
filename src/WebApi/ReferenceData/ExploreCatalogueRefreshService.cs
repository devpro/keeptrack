using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Rebuilds the stored copy of each discovery provider's "best of" ranking (<c>explore_catalogue</c>), so Explore's read path never calls a provider.
/// <para>
/// A ranking is a global fact: every user reads the same list, only the exclusions differing.
/// Built once a week, it costs no provider call per page load, add or dismiss, and a database query pages it as deep as <see cref="CatalogueDepth"/>.
/// </para>
/// </summary>
public class ExploreCatalogueRefreshService(
    ITmdbClient tmdbClient,
    ReferenceClientRegistry<IVideoGameReferenceClient> videoGameClients,
    ExploreRankings exploreRankings,
    IOmdbClient omdbClient,
    IOmdbCallBudget omdbCallBudget,
    IAppSettingRepository appSettingRepository,
    RatingSourceOptions ratingSourceOptions,
    IExploreCatalogueRepository catalogueRepository,
    ILogger<ExploreCatalogueRefreshService> logger)
{
    /// <summary>
    /// How many ranked titles to keep per ordering, a few thousand small documents in all, about 150 provider calls a week.
    /// It sets how far a user can scroll, and raising it costs one provider call per page of depth per week, nothing on the read path.
    /// </summary>
    public const int CatalogueDepth = 1000;

    /// <summary>
    /// The most entries one pass loads to attempt an IMDb rating for, per domain: a query bound, not the budget.
    /// A pass spends what the shared OMDb allowance has left after the reference sync, which runs first on the same tick (see <see cref="OmdbCallBudget"/>).
    /// <para>
    /// Stored values are never fetched again, and an attempt OMDb answered is stamped, so passes walk down the ranking and coverage converges over a few days.
    /// </para>
    /// </summary>
    private const int MaxBackfillPerPass = 1000;

    /// <summary>
    /// Refreshes every (domain, ordering) older than <paramref name="staleAfter"/>, <see cref="TimeSpan.Zero"/> forcing a full rebuild, then spends the pass's backfill budget.
    /// A failing ordering is logged and the next attempted, as <see cref="ReferenceSyncService"/> does with a document.
    /// </summary>
    public async Task<ExploreCatalogueRefreshResult> RefreshAsync(TimeSpan staleAfter, CancellationToken cancellationToken = default)
    {
        var rankingsRefreshed = 0;
        var entriesRefreshed = 0;

        foreach (var (type, ranking) in exploreRankings.All)
        {
            try
            {
                if (!await IsStaleAsync(type, ranking, staleAfter)) continue;

                entriesRefreshed += await RefreshRankingAsync(type, ranking, cancellationToken);
                rankingsRefreshed++;
            }
            // one failing ranking does not abort the pass, but a shutdown does, or every remaining ranking would log a disposed-container failure
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "Explore catalogue refresh failed for {ItemType}/{Ranking}.", type, ranking);
            }
        }

        // Rankings the configuration no longer maintains, after a provider change, are dropped rather than left unreadable forever.
        // Keyed on what is declared, not on what this pass fetched, so a skipped or failed ranking is never touched.
        await catalogueRepository.DeleteRankingsExceptAsync(exploreRankings.All.Select(r => r.Ranking).Distinct().ToList());

        return new ExploreCatalogueRefreshResult(rankingsRefreshed, entriesRefreshed, await BackfillImdbAsync(cancellationToken));
    }

    private async Task<bool> IsStaleAsync(ExploreItemType type, string ranking, TimeSpan staleAfter)
    {
        var oldest = await catalogueRepository.FindOldestRefreshedAtAsync(type, ranking);
        return oldest is null || DateTime.UtcNow - oldest.Value >= staleAfter;
    }

    /// <summary>
    /// Pages through the provider once, writing each title with its 1-based position, then drops what left the ranking.
    /// The prune runs only after a complete walk, so a failed or empty pass leaves the previous catalogue, a stale list being far better than an empty Explore page.
    /// </summary>
    private async Task<int> RefreshRankingAsync(ExploreItemType type, string ranking, CancellationToken cancellationToken)
    {
        var passStartedAt = DateTime.UtcNow;
        var fetch = TopRatedFetcher(type, ranking);
        var rank = 0;

        for (var page = 1; rank < CatalogueDepth; page++)
        {
            var items = await fetch(page, cancellationToken);
            if (items.Count == 0) break; // past the provider's last page

            var entries = new List<ExploreCatalogueEntryModel>();
            foreach (var item in items)
            {
                if (rank >= CatalogueDepth) break;
                entries.Add(ToEntry(type, ranking, item, ++rank, passStartedAt));
            }

            await catalogueRepository.UpsertManyAsync(entries);
        }

        if (rank == 0)
        {
            logger.LogWarning("Explore catalogue refresh for {ItemType}/{Ranking} returned no titles; keeping the previous catalogue.", type, ranking);
            return 0;
        }

        var dropped = await catalogueRepository.DeleteStaleAsync(type, ranking, passStartedAt);
        logger.LogInformation(
            "Explore catalogue refreshed for {ItemType}/{Ranking}: {Ranked} title(s) ranked, {Dropped} dropped out.", type, ranking, rank, dropped);
        return rank;
    }

    /// <summary>
    /// Fills the IMDb half of movie and TV entries, top of the ranking first: the missing ratings, within the day's shared OMDb allowance (see <see cref="OmdbCallBudget"/>), and the IMDb page link.
    /// The link costs no allowance, made from the id the rating lookup resolves anyway.
    /// <para>
    /// It runs only for a domain showing IMDb, the value being display only, since ranking by partial OMDb data would float unrated titles up.
    /// The admin's "force TMDB" flag skips it.
    /// </para>
    /// <para>
    /// The remaining allowance, read once per domain, only sizes the query, and each call is reserved in the client, so another replica spending meanwhile cannot push the pass over the limit.
    /// </para>
    /// </summary>
    private async Task<int> BackfillImdbAsync(CancellationToken cancellationToken)
    {
        if (await appSettingRepository.GetExploreUseTmdbAsync()) return 0;

        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var backfilled = 0;

        foreach (var type in new[] { ExploreItemType.Movie, ExploreItemType.TvShow })
        {
            if (ratingSourceOptions.Resolve(overrides, ExploreRankings.ToReferenceItemType(type)) != RatingSourceCatalog.Imdb) continue;

            var affordable = await omdbCallBudget.GetRemainingAsync(OmdbCallPriority.Background, cancellationToken);
            if (affordable <= 0)
            {
                logger.LogInformation("IMDb rating backfill skipped for {ItemType}: no OMDb calls left in today's budget.", type);
                continue;
            }

            var ranking = exploreRankings.For(type, RatingSourceCatalog.Imdb);
            var pending = await catalogueRepository.FindMissingRatingOrLinkAsync(
                type, ranking, RatingSourceCatalog.Imdb, DateTime.UtcNow - RatingSourceCatalog.RatingReattemptAfter, Math.Min(MaxBackfillPerPass, affordable));
            var imdbIdFetcher = ImdbIdFetcher(type);

            foreach (var entry in pending)
            {
                try
                {
                    var imdbId = await imdbIdFetcher(entry.ExternalId, cancellationToken);

                    // the link is made from the id, stored as it resolves, whether or not the budget allows the rating lookup
                    if (!string.IsNullOrEmpty(imdbId) && !entry.WebUrls.ContainsKey(RatingSourceCatalog.Imdb))
                    {
                        await catalogueRepository.SetWebUrlAsync(
                            type, ranking, entry.ExternalId, RatingSourceCatalog.Imdb, ProviderWebLinks.Imdb(imdbId));
                    }

                    // an entry loaded only for its missing link has its rating, and buying it again would take budget from entries with none
                    if (entry.Ratings.ContainsKey(RatingSourceCatalog.Imdb)) continue;

                    var lookup = string.IsNullOrEmpty(imdbId)
                        ? OmdbLookupResult.NoRating // TMDB has no IMDb id for it, a real answer worth stamping
                        : await omdbClient.GetRatingAsync(imdbId, OmdbCallPriority.Background, cancellationToken);

                    // Only a real answer is stamped, so a title OMDb has nothing for is not retried next pass, holding the budget.
                    // A call that never happened leaves no stamp, or an exhausted afternoon would write those titles off for the whole window.
                    if (lookup.Attempted)
                    {
                        await catalogueRepository.RecordRatingAttemptAsync(type, ranking, entry.ExternalId, RatingSourceCatalog.Imdb, lookup.Rating?.Value);
                        if (lookup.Rating is not null) backfilled++;
                    }
                    else if (omdbCallBudget.IsExhausted(OmdbCallPriority.Background))
                    {
                        // nothing left to spend, so every remaining entry would waste a TMDB call
                        logger.LogInformation("IMDb rating backfill stopped for {ItemType}: today's OMDb budget is spent.", type);
                        break;
                    }
                }
                // like the ranking catch: one entry may fail, a shutdown is never ignored
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.LogError(exception, "IMDb rating backfill failed for {ItemType} {ExternalId}.", type, entry.ExternalId);
                }
            }
        }

        return backfilled;
    }

    // Which client answers for a (domain, ordering): TMDB has one top-rated list per domain, and the game provider orders by whichever of its sources the ordering names.
    // Each arm names the source key its page links are stored under, the discovery provider's.
    private Func<int, CancellationToken, Task<IReadOnlyList<CatalogueItem>>> TopRatedFetcher(ExploreItemType type, string ranking) => type switch
    {
        ExploreItemType.Movie => async (page, token) => ToItems(await tmdbClient.GetTopRatedMoviesAsync(page, token), RatingSourceCatalog.Tmdb),
        ExploreItemType.TvShow => async (page, token) => ToItems(await tmdbClient.GetTopRatedTvShowsAsync(page, token), RatingSourceCatalog.Tmdb),
        ExploreItemType.VideoGame => async (page, token) =>
        {
            var client = videoGameClients.Resolve(null);
            return ToItems(await client.GetTopRatedGamesAsync(page, ranking, token), client.ProviderKey);
        }
        ,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private Func<string, CancellationToken, Task<string?>> ImdbIdFetcher(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => tmdbClient.GetMovieImdbIdAsync,
        ExploreItemType.TvShow => tmdbClient.GetTvShowImdbIdAsync,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static List<CatalogueItem> ToItems(IReadOnlyList<TmdbTopRatedItem> items, string providerKey) =>
    [
        .. items.Select(i => new CatalogueItem(
            i.TmdbId, i.Title, i.Year, i.Synopsis, i.PosterUrl,
            RatingsOf((RatingSourceCatalog.Tmdb, i.VoteAverage)), WebUrlsOf(providerKey, i.WebUrl)))
    ];

    // a game provider reports every score on each entry, all stored whatever the ordering, so switching the selection costs no call, the client having keyed them already
    private static List<CatalogueItem> ToItems(IReadOnlyList<VideoGameTopRatedItem> items, string providerKey) =>
    [
        .. items.Select(i => new CatalogueItem(i.ExternalId, i.Title, i.Year, null, i.ImageUrl, i.Ratings, WebUrlsOf(providerKey, i.WebUrl)))
    ];

    private static Dictionary<string, double> RatingsOf(params (string Source, double? Value)[] ratings) =>
        ratings.Where(r => r.Value is not null).ToDictionary(r => r.Source, r => r.Value!.Value);

    // a provider giving no page URL adds no key, and the card falls back to another link rather than a dead one
    private static Dictionary<string, string> WebUrlsOf(string providerKey, string? webUrl) =>
        string.IsNullOrWhiteSpace(webUrl) ? [] : new Dictionary<string, string> { [providerKey] = webUrl };

    private static ExploreCatalogueEntryModel ToEntry(ExploreItemType type, string ranking, CatalogueItem item, int rank, DateTime refreshedAt) => new()
    {
        ItemType = type,
        Ranking = ranking,
        ExternalId = item.ExternalId,
        Rank = rank,
        Title = item.Title,
        Year = item.Year,
        Synopsis = item.Synopsis,
        ImageUrl = item.ImageUrl,
        Ratings = item.Ratings,
        WebUrls = item.WebUrls,
        RefreshedAt = refreshedAt
    };

    /// <summary>
    /// One provider listing entry, normalized so the paging and storing loop is written once.
    /// </summary>
    private sealed record CatalogueItem(
        string ExternalId,
        string Title,
        int? Year,
        string? Synopsis,
        string? ImageUrl,
        Dictionary<string, double> Ratings,
        Dictionary<string, string> WebUrls);
}

/// <summary>
/// What one catalogue refresh pass did, folded into the reference sync's result, so a plain record rather than a contract DTO.
/// </summary>
public sealed record ExploreCatalogueRefreshResult(int RankingsRefreshed, int EntriesRefreshed, int ImdbRatingsBackfilled);

/// <summary>
/// Folds a refresh pass's counts into the reference sync result.
/// An extension, since <see cref="ReferenceSyncResultDto"/> lives in WebApi.Contracts, which does not know this service's types.
/// </summary>
public static class ExploreCatalogueRefreshResultExtensions
{
    public static void ApplyExploreRefresh(this ReferenceSyncResultDto result, ExploreCatalogueRefreshResult refresh)
    {
        result.ExploreRankingsRefreshed = refresh.RankingsRefreshed;
        result.ExploreEntriesRefreshed = refresh.EntriesRefreshed;
        result.ExploreImdbRatingsBackfilled = refresh.ImdbRatingsBackfilled;
    }
}
