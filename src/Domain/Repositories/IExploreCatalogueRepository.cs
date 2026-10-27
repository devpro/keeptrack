using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for the stored Explore rankings (<see cref="ExploreCatalogueEntryModel"/>).
/// Not an <see cref="IDataRepository{TModel}"/>, since the collection is owner-less and paged by rank rather than by owner-scoped skip and limit.
/// </summary>
public interface IExploreCatalogueRepository
{
    /// <summary>
    /// The next <paramref name="take"/> entries of a ranking after position <paramref name="afterRank"/> (0 for the first page), in rank order.
    /// The read path's only query.
    /// </summary>
    Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindRankedAsync(ExploreItemType type, string ranking, int afterRank, int take);

    /// <summary>
    /// The highest-ranked entries still missing something from <paramref name="source"/>, at most <paramref name="take"/>: the work list of the backfill.
    /// Ordered by rank, so coverage fills from the top of the list down.
    /// An entry qualifies when either:
    /// <list type="bullet">
    /// <item>its rating is missing and was not attempted since <paramref name="notAttemptedSince"/>,
    /// which stops titles the source has nothing for spending the budget on every pass;</item>
    /// <item>its <see cref="ExploreCatalogueEntryModel.WebUrls"/> link is missing although it has a rating.</item>
    /// </list>
    /// A rated entry without a link had its provider id resolved before links were stored, so one lookup closes it for good.
    /// That half carries no window, which would delay a link available now, and still terminates:
    /// an entry with no provider id never gets a rating either, so only the first half, with its window, can match it.
    /// </summary>
    Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindMissingRatingOrLinkAsync(
        ExploreItemType type, string ranking, string source, DateTime notAttemptedSince, int take);

    /// <summary>
    /// Inserts or updates entries by their natural key (item type, ranking, external id).
    /// Ratings and web links are merged key by key, never replaced whole, so a value only the backfill obtains survives every ordinary refresh.
    /// </summary>
    Task UpsertManyAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries);

    /// <summary>
    /// Records the entry's page on <paramref name="source"/>'s website.
    /// Separate from <see cref="RecordRatingAttemptAsync"/>, since a link is worth keeping once the provider id resolves,
    /// even when the rating lookup never happened (no key, spent budget, failed request).
    /// </summary>
    Task SetWebUrlAsync(ExploreItemType type, string ranking, string externalId, string source, string webUrl);

    /// <summary>
    /// Records the outcome of a rating lookup: it always stamps the attempt, and stores the value when there is one.
    /// Stamping a fruitless attempt moves the next pass's budget down the list.
    /// </summary>
    Task RecordRatingAttemptAsync(ExploreItemType type, string ranking, string externalId, string ratingSource, double? value);

    /// <summary>
    /// Removes the entries of a ranking that a completed pass did not rewrite, those that dropped out of the provider's list.
    /// Called only after a pass finishes, so a run failing halfway leaves the previous catalogue serving rather than emptying it.
    /// </summary>
    Task<long> DeleteStaleAsync(ExploreItemType type, string ranking, DateTime refreshedBefore);

    /// <summary>
    /// The oldest refresh stamp in a ranking, or null when it is empty: the staleness signal the scheduler reads.
    /// A pass dying partway leaves its written entries freshly stamped, so the newest stamp would read as "just refreshed" and skip the retry.
    /// The oldest only advances once a pass completes and prunes what it did not rewrite.
    /// </summary>
    Task<DateTime?> FindOldestRefreshedAtAsync(ExploreItemType type, string ranking);

    /// <summary>How many entries a ranking holds, only to tell "nothing new for this caller" from "not built yet".</summary>
    Task<long> CountAsync(ExploreItemType type, string ranking);

    /// <summary>
    /// Removes every entry of a ranking no longer maintained, whose key is not in <paramref name="rankings"/>.
    /// <see cref="DeleteStaleAsync"/> only prunes within a ranking a pass rewrote, so a ranking no longer written, after a provider change, would stay forever.
    /// Safe on every pass, since the argument is what the configuration declares, not what one pass fetched.
    /// </summary>
    Task<long> DeleteRankingsExceptAsync(IReadOnlyCollection<string> rankings);
}
