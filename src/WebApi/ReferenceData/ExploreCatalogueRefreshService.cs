using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Rebuilds the local copy of each discovery provider's "best of" ranking (<c>explore_catalogue</c>), so the
/// Explore read path never calls a provider.
/// <para>
/// This is the whole point of the catalogue. The ranking is a *global* fact - every user's Explore page reads
/// the same list, with only the exclusion half ("do I already track this?") differing - so paying for it per
/// request was pure duplicated work: a page load re-pulled the provider's first pages, and so did every add
/// and every dismiss that topped the list back up. Paying for it once a week instead both removes that
/// traffic and lifts the ceiling it forced: a request could only ever afford a handful of provider pages, so
/// Explore could never show more than the top ~100 titles no matter how many the user had already worked
/// through. A stored ranking is paged with a database query, so <see cref="CatalogueDepth"/> is now a storage
/// decision rather than a per-request latency budget.
/// </para>
/// <para>
/// Lives in WebApi/ReferenceData beside <see cref="ExploreService"/> because it depends on the provider
/// clients, the same reason that one does.
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
    /// How many ranked titles to keep per ordering. Four orderings at this depth is a few thousand small
    /// documents - trivial storage, and about 150 provider calls a week to maintain. It is the knob for "how
    /// far can a user keep scrolling"; raising it costs one extra provider call per page of depth, once a
    /// week, and nothing at all on the read path.
    /// </summary>
    public const int CatalogueDepth = 1000;

    /// <summary>
    /// The most entries one pass will pull into memory to attempt an IMDb rating for, per domain - a query
    /// bound, not the budget. What a pass may actually spend is whatever the shared daily OMDb allowance has
    /// left after the reference sync (which runs first on the same tick) has taken its share: see
    /// <see cref="OmdbCallBudget"/>. This used to be a hardcoded 250 per domain, which had to assume the worst
    /// about the other consumer and so under-spent a quiet day and over-spent a busy one.
    /// <para>
    /// Values already stored are never re-fetched and attempts are stamped whenever OMDb actually answered, so
    /// successive passes walk down the ranking instead of re-attempting the top - coverage converges over a
    /// few days and self-corrects when new titles enter the list.
    /// </para>
    /// </summary>
    private const int MaxBackfillPerPass = 1000;

    /// <summary>
    /// Refreshes every (domain, ordering) whose stored copy is older than <paramref name="staleAfter"/>, then
    /// spends this pass's rating-backfill budget. Pass <see cref="TimeSpan.Zero"/> to force a full rebuild.
    /// One failing ordering never aborts the run - it is logged and the next is attempted, the same way
    /// <see cref="ReferenceSyncService"/> treats one failing document.
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
            // see ReferenceSyncService's own per-item catch: one failing ranking must not abort the pass, but a
            // shutdown must, or every remaining ranking logs its own disposed-container failure in turn.
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                logger.LogError(exception, "Explore catalogue refresh failed for {ItemType}/{Ranking}.", type, ranking);
            }
        }

        // rankings the current configuration no longer maintains (a domain's discovery provider changed, so
        // its orderings changed with it) are dropped here rather than left to sit unreadable forever. Keyed on
        // what is declared, not on what this pass fetched, so a skipped or failed ranking is never affected.
        await catalogueRepository.DeleteRankingsExceptAsync(exploreRankings.All.Select(r => r.Ranking).Distinct().ToList());

        return new ExploreCatalogueRefreshResult(rankingsRefreshed, entriesRefreshed, await BackfillImdbRatingsAsync(cancellationToken));
    }

    private async Task<bool> IsStaleAsync(ExploreItemType type, string ranking, TimeSpan staleAfter)
    {
        var oldest = await catalogueRepository.FindOldestRefreshedAtAsync(type, ranking);
        return oldest is null || DateTime.UtcNow - oldest.Value >= staleAfter;
    }

    /// <summary>
    /// Pages through the provider once, writing each title with its 1-based position, then drops whatever
    /// dropped out of the ranking. The prune runs only after the walk completed: a pass that failed or came
    /// back empty leaves the previous catalogue in place, because a stale list is a far better answer than an
    /// empty Explore page.
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
    /// Fills in IMDb ratings for the movie/TV entries still missing one, top of the ranking first, spending
    /// whatever is left of the day's shared OMDb allowance (see <see cref="OmdbCallBudget"/>).
    /// <para>
    /// Only runs for a domain IMDb actually won: the value is display-only (the ordering stays TMDB's, since
    /// re-ranking by partial OMDb data would float unrated titles to the top), so fetching it for a domain
    /// showing TMDB numbers would buy nothing. The admin's "force TMDB" flag skips it entirely, which is what
    /// that flag has always been for - it just no longer has to be honoured on a per-request basis.
    /// </para>
    /// <para>
    /// The remaining allowance is read once per domain and used to size the query, then each entry's call is
    /// reserved individually inside the client - the read only decides how much work to pull, it never
    /// authorizes a call, so another replica spending concurrently can't push this pass over the limit.
    /// </para>
    /// </summary>
    private async Task<int> BackfillImdbRatingsAsync(CancellationToken cancellationToken)
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
            var pending = await catalogueRepository.FindMissingRatingAsync(
                type, ranking, RatingSourceCatalog.Imdb, DateTime.UtcNow - RatingSourceCatalog.RatingReattemptAfter, Math.Min(MaxBackfillPerPass, affordable));
            var imdbIdFetcher = ImdbIdFetcher(type);

            foreach (var entry in pending)
            {
                try
                {
                    var imdbId = await imdbIdFetcher(entry.ExternalId, cancellationToken);
                    var lookup = string.IsNullOrEmpty(imdbId)
                        ? OmdbLookupResult.NoRating // TMDB has no imdb id for it at all: a real answer, worth stamping
                        : await omdbClient.GetRatingAsync(imdbId, OmdbCallPriority.Background, cancellationToken);

                    // only a real answer is stamped. A title OMDb has nothing for must not be retried next
                    // pass, or it would hold the budget and coverage would never move down the list - but a
                    // call that never happened (budget spent, request failed) must leave no stamp, or an
                    // exhausted afternoon would write those titles off for the whole re-attempt window.
                    if (lookup.Attempted)
                    {
                        await catalogueRepository.RecordRatingAttemptAsync(type, ranking, entry.ExternalId, RatingSourceCatalog.Imdb, lookup.Rating?.Value);
                        if (lookup.Rating is not null) backfilled++;
                    }
                    else if (omdbCallBudget.IsExhausted(OmdbCallPriority.Background))
                    {
                        // nothing left to spend, so every remaining entry would be a wasted TMDB call
                        logger.LogInformation("IMDb rating backfill stopped for {ItemType}: today's OMDb budget is spent.", type);
                        break;
                    }
                }
                // same rule as the per-ranking catch above: one entry may fail, a shutdown may not be ignored
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    logger.LogError(exception, "IMDb rating backfill failed for {ItemType} {ExternalId}.", type, entry.ExternalId);
                }
            }
        }

        return backfilled;
    }

    // which client answers for a (domain, ordering). TMDB has one top-rated list per domain; the video game
    // provider orders natively by whichever of its own sources the ordering names.
    private Func<int, CancellationToken, Task<IReadOnlyList<CatalogueItem>>> TopRatedFetcher(ExploreItemType type, string ranking) => type switch
    {
        ExploreItemType.Movie => async (page, token) => ToItems(await tmdbClient.GetTopRatedMoviesAsync(page, token)),
        ExploreItemType.TvShow => async (page, token) => ToItems(await tmdbClient.GetTopRatedTvShowsAsync(page, token)),
        ExploreItemType.VideoGame => async (page, token) => ToItems(await videoGameClients.Resolve(null).GetTopRatedGamesAsync(page, ranking, token)),
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private Func<string, CancellationToken, Task<string?>> ImdbIdFetcher(ExploreItemType type) => type switch
    {
        ExploreItemType.Movie => tmdbClient.GetMovieImdbIdAsync,
        ExploreItemType.TvShow => tmdbClient.GetTvShowImdbIdAsync,
        _ => throw new ArgumentOutOfRangeException(nameof(type), $"Explore is not available for {type}.")
    };

    private static List<CatalogueItem> ToItems(IReadOnlyList<TmdbTopRatedItem> items) =>
    [
        .. items.Select(i => new CatalogueItem(
            i.TmdbId, i.Title, i.Year, i.Synopsis, i.PosterUrl, Ratings((RatingSourceCatalog.Tmdb, i.VoteAverage))))
    ];

    // a video game provider reports every score it has on each listing entry, so all of them are stored
    // whichever one the list was ordered by - switching the admin's selection then costs no provider call at
    // all. The client has already keyed them by its own sources, so there is nothing to map per provider here.
    private static List<CatalogueItem> ToItems(IReadOnlyList<VideoGameTopRatedItem> items) =>
    [
        .. items.Select(i => new CatalogueItem(i.ExternalId, i.Title, i.Year, null, i.ImageUrl, i.Ratings))
    ];

    private static Dictionary<string, double> Ratings(params (string Source, double? Value)[] ratings) =>
        ratings.Where(r => r.Value is not null).ToDictionary(r => r.Source, r => r.Value!.Value);

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
        RefreshedAt = refreshedAt
    };

    /// <summary>
    /// One provider listing entry, normalized across providers so the paging/storing loop above is written
    /// once instead of per domain.
    /// </summary>
    private sealed record CatalogueItem(
        string ExternalId, string Title, int? Year, string? Synopsis, string? ImageUrl, Dictionary<string, double> Ratings);
}

/// <summary>
/// What one catalogue refresh pass did. Internal to the API (it is folded into the reference-sync job's own
/// result for reporting), so it is a plain record rather than a contract DTO.
/// </summary>
public sealed record ExploreCatalogueRefreshResult(int RankingsRefreshed, int EntriesRefreshed, int ImdbRatingsBackfilled);

/// <summary>
/// Folds a refresh pass's counts into the reference-sync result both the periodic pass and the admin's "sync
/// now" report through. An extension rather than members on <see cref="ReferenceSyncResultDto"/> because that
/// DTO lives in WebApi.Contracts, which doesn't (and shouldn't) know this service's types.
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
