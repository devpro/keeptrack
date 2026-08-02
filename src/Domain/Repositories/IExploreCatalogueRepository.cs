using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Repositories;

/// <summary>
/// Persistence for the materialized Explore rankings (<see cref="ExploreCatalogueEntryModel"/>).
/// Purpose-built rather than <see cref="IDataRepository{TModel}"/>: the collection is owner-less and paged by
/// rank, not by the owner-scoped skip/limit that base is hard-constrained to - the same reasoning as the
/// <c>*_reference</c> repositories.
/// </summary>
public interface IExploreCatalogueRepository
{
    /// <summary>
    /// The next <paramref name="take"/> entries of a ranking after position <paramref name="afterRank"/>, in
    /// rank order. Pass 0 for the first page. The read path's only query.
    /// </summary>
    Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindRankedAsync(ExploreItemType type, string ranking, int afterRank, int take);

    /// <summary>
    /// The highest-ranked entries still missing <paramref name="ratingSource"/> that haven't been attempted
    /// since <paramref name="notAttemptedSince"/>, capped at <paramref name="take"/> - the work list for the
    /// bounded per-pass rating backfill. Ordered by rank so coverage fills from the top of the list down.
    /// </summary>
    Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindMissingRatingAsync(
        ExploreItemType type, string ranking, string ratingSource, DateTime notAttemptedSince, int take);

    /// <summary>
    /// Inserts or updates entries by their natural key (item type, ranking, external id). Ratings are merged
    /// key by key, never replaced wholesale, so a value only one backfill pass knows how to obtain survives
    /// every ordinary refresh.
    /// </summary>
    Task UpsertManyAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries);

    /// <summary>
    /// Records the outcome of a rating lookup: stamps the attempt (always) and stores the value (only when
    /// there is one). Stamping a fruitless attempt is what keeps the next pass's budget moving down the list.
    /// </summary>
    Task RecordRatingAttemptAsync(ExploreItemType type, string ranking, string externalId, string ratingSource, double? value);

    /// <summary>
    /// Removes the entries of a ranking that a completed pass didn't rewrite - i.e. those that dropped out of
    /// the provider's list. Called only after a pass finishes, so a run that fails halfway leaves the previous
    /// catalogue serving rather than emptying it.
    /// </summary>
    Task<long> DeleteStaleAsync(ExploreItemType type, string ranking, DateTime refreshedBefore);

    /// <summary>
    /// The *oldest* refresh stamp in a ranking, or null when the ranking is empty - the staleness signal the
    /// scheduler reads. Deliberately the oldest and not the newest: a pass that died partway leaves its
    /// already-written entries freshly stamped, and taking the newest would read that as "just refreshed" and
    /// skip the retry. The oldest only advances once a pass completed and pruned what it didn't rewrite.
    /// </summary>
    Task<DateTime?> FindOldestRefreshedAtAsync(ExploreItemType type, string ranking);

    /// <summary>How many entries a ranking holds - used only to tell "nothing new for you" apart from "not built yet".</summary>
    Task<long> CountAsync(ExploreItemType type, string ranking);
}
