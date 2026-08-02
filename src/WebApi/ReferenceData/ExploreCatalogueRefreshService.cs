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
    IRawgClient rawgClient,
    IOmdbClient omdbClient,
    IAppSettingRepository appSettingRepository,
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
    /// How many entries one pass may attempt an IMDb rating for, per domain. IMDb ratings are the one thing
    /// the listings don't carry: each costs two calls (TMDB for the imdb id, then OMDb), and OMDb's free tier
    /// is 1000 a day, so enriching a full <see cref="CatalogueDepth"/> in a single pass is not affordable.
    /// Values already stored are never re-fetched and attempts are stamped either way, so successive passes
    /// walk down the ranking instead of re-attempting the top - coverage converges over a few weeks and
    /// self-corrects when new titles enter the list.
    /// </summary>
    private const int ImdbBackfillBudget = 250;

    /// <summary>
    /// How long before a fruitless rating attempt is worth retrying. Without it, the handful of titles OMDb
    /// has no rating for would consume the same budget every pass and coverage would never advance past them.
    /// </summary>
    private static readonly TimeSpan s_ratingReattemptAfter = TimeSpan.FromDays(90);

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

        foreach (var (type, ranking) in ExploreRankings.All)
        {
            try
            {
                if (!await IsStaleAsync(type, ranking, staleAfter)) continue;

                entriesRefreshed += await RefreshRankingAsync(type, ranking, cancellationToken);
                rankingsRefreshed++;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Explore catalogue refresh failed for {ItemType}/{Ranking}.", type, ranking);
            }
        }

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
    /// Fills in IMDb ratings for the movie/TV entries still missing one, top of the ranking first and bounded
    /// by <see cref="ImdbBackfillBudget"/>.
    /// <para>
    /// Only runs for a domain IMDb actually won: the value is display-only (the ordering stays TMDB's, since
    /// re-ranking by partial OMDb data would float unrated titles to the top), so fetching it for a domain
    /// showing TMDB numbers would buy nothing. The admin's "force TMDB" flag skips it entirely, which is what
    /// that flag has always been for - it just no longer has to be honoured on a per-request basis.
    /// </para>
    /// </summary>
    private async Task<int> BackfillImdbRatingsAsync(CancellationToken cancellationToken)
    {
        if (await appSettingRepository.GetExploreUseTmdbAsync()) return 0;

        var overrides = await appSettingRepository.GetReferenceRatingSourcesAsync();
        var backfilled = 0;

        foreach (var type in new[] { ExploreItemType.Movie, ExploreItemType.TvShow })
        {
            if (RatingSourceCatalog.Resolve(overrides, ExploreRankings.ToReferenceItemType(type)) != RatingSourceCatalog.Imdb) continue;

            var ranking = ExploreRankings.For(type, RatingSourceCatalog.Imdb);
            var pending = await catalogueRepository.FindMissingRatingAsync(
                type, ranking, RatingSourceCatalog.Imdb, DateTime.UtcNow - s_ratingReattemptAfter, ImdbBackfillBudget);
            var imdbIdFetcher = ImdbIdFetcher(type);

            foreach (var entry in pending)
            {
                try
                {
                    var imdbId = await imdbIdFetcher(entry.ExternalId, cancellationToken);
                    var rating = string.IsNullOrEmpty(imdbId) ? null : await omdbClient.GetRatingAsync(imdbId, cancellationToken);
                    // the attempt is recorded either way - a title OMDb has nothing for must not be retried
                    // next pass, or it would hold the budget and coverage would never move down the list.
                    await catalogueRepository.RecordRatingAttemptAsync(type, ranking, entry.ExternalId, RatingSourceCatalog.Imdb, rating?.Value);
                    if (rating is not null) backfilled++;
                }
                catch (Exception exception)
                {
                    logger.LogError(exception, "IMDb rating backfill failed for {ItemType} {ExternalId}.", type, entry.ExternalId);
                }
            }
        }

        return backfilled;
    }

    // which client answers for a (domain, ordering). TMDB has one top-rated list per domain; RAWG orders
    // natively by whichever of its own sources the ordering names.
    private Func<int, CancellationToken, Task<IReadOnlyList<CatalogueItem>>> TopRatedFetcher(ExploreItemType type, string ranking) => type switch
    {
        ExploreItemType.Movie => async (page, token) => ToItems(await tmdbClient.GetTopRatedMoviesAsync(page, token)),
        ExploreItemType.TvShow => async (page, token) => ToItems(await tmdbClient.GetTopRatedTvShowsAsync(page, token)),
        ExploreItemType.VideoGame => async (page, token) => ToItems(await rawgClient.GetTopRatedGamesAsync(page, ranking, token)),
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

    // RAWG reports both of its scores on every listing entry, so both are stored whichever one the list was
    // ordered by - switching the admin's selection then costs no provider call at all.
    private static List<CatalogueItem> ToItems(IReadOnlyList<RawgTopRatedItem> items) =>
    [
        .. items.Select(i => new CatalogueItem(
            i.ExternalId, i.Title, i.Year, null, i.ImageUrl,
            Ratings((RatingSourceCatalog.Rawg, i.Rating), (RatingSourceCatalog.Metacritic, i.Metacritic))))
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
