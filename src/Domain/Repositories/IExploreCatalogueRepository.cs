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
    /// The highest-ranked entries that still have something to learn about <paramref name="source"/>, capped
    /// at <paramref name="take"/> - the work list for the bounded per-pass backfill. Ordered by rank so
    /// coverage fills from the top of the list down. An entry qualifies when either:
    /// <list type="bullet">
    /// <item>its rating is missing and it hasn't been attempted since <paramref name="notAttemptedSince"/> -
    /// the window that stops the titles the source genuinely has nothing for from burning the whole budget on
    /// every pass, forever;</item>
    /// <item>or its <see cref="ExploreCatalogueEntryModel.WebUrls"/> link is missing *while it already has a
    /// rating*. That combination means a previous pass resolved the provider id but predates links being
    /// stored, so one lookup closes it for good - which is why this half deliberately carries no re-attempt
    /// window (it would make every already-rated entry wait up to 90 days for a link it could have today) and
    /// still terminates: an entry the provider has no id for never gets a rating either, so it can only ever
    /// match through the first bullet, where the window applies.</item>
    /// </list>
    /// </summary>
    Task<IReadOnlyList<ExploreCatalogueEntryModel>> FindMissingRatingOrLinkAsync(
        ExploreItemType type, string ranking, string source, DateTime notAttemptedSince, int take);

    /// <summary>
    /// Inserts or updates entries by their natural key (item type, ranking, external id). Ratings and web
    /// links are merged key by key, never replaced wholesale, so a value only one backfill pass knows how to
    /// obtain survives every ordinary refresh.
    /// </summary>
    Task UpsertManyAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries);

    /// <summary>
    /// Records where a human can read more about an entry on <paramref name="source"/>'s own website. Separate
    /// from <see cref="RecordRatingAttemptAsync"/> on purpose: a link is worth keeping the moment the provider
    /// id resolves, even when the rating lookup that usually follows never happened (no key, spent budget,
    /// failed request) - gating it on the rating's outcome would throw away a fact already in hand.
    /// </summary>
    Task SetWebUrlAsync(ExploreItemType type, string ranking, string externalId, string source, string webUrl);

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

    /// <summary>
    /// Removes every entry belonging to a ranking that is no longer maintained - i.e. whose key isn't in
    /// <paramref name="rankings"/>. <see cref="DeleteStaleAsync"/> can't do this: it prunes *within* a ranking
    /// a pass just rewrote, so a ranking that stopped being written at all (because the domain's discovery
    /// provider changed, and its orderings changed with it) would sit in the collection forever, stale and
    /// unreadable. Safe to run on every pass because the argument is what the current configuration declares,
    /// not what one pass happened to fetch.
    /// </summary>
    Task<long> DeleteRankingsExceptAsync(IReadOnlyCollection<string> rankings);
}
