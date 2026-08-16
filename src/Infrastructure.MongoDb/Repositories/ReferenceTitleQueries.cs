using System.Collections.Generic;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The title-only reference lookup, written once for all five reference collections - they differ only in the
/// filter each builds (books and albums additionally narrow by creator), exactly like
/// <see cref="ReferenceStalenessQueries"/>'s per-domain field expressions.
/// </summary>
internal static class ReferenceTitleQueries
{
    /// <summary>
    /// The <b>single</b> document matching <paramref name="filter"/>, or null when none matches <b>or when
    /// several do</b>.
    /// <para>
    /// Backs <c>FindByTitleAsync</c>, which is only ever reached when the caller has no year to identify the
    /// work with (see <c>ReferenceEnrichmentService.TryLinkExisting*ReferenceAsync</c>). It used to be a plain
    /// <c>FirstOrDefaultAsync</c> over an unsorted, unbounded match, so where several reference documents share
    /// a title it returned whichever one the database happened to hand back first - a guess dressed up as an
    /// answer, and one that is stable enough to look deliberate. Reported from the running app: a yearless
    /// "Resident Evil 2" silently adopted the 2019 remake's reference, and did it again after the link was
    /// deleted. IGDB holds eight games named exactly "Resident Evil 2".
    /// </para>
    /// <para>
    /// <b>"Ambiguous" and "no match" are the same answer to a caller that must not guess</b>, so both are null
    /// - which is why this needs no new call site handling: every caller already treats null as "leave it
    /// unresolved". A single match is untouched, and that is the ordinary case the title-only lookup exists
    /// for.
    /// </para>
    /// <para>
    /// This is the half of the "Road House" finding that was never closed (see
    /// <c>docs/code-quality-findings.md</c>): that fix stopped a <i>known</i> year from being ignored, and left
    /// the yearless case picking arbitrarily.
    /// </para>
    /// <para>
    /// Deliberately <b>not</b> applied to <c>FindByTitleYearAsync</c>. Two documents sharing a title <i>and</i>
    /// a year are a duplicate to be merged, not an ambiguity to refuse - they are the same work, so either
    /// answers the question, and refusing would break linking until an admin merged them.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Reads two documents, never a count: "is there more than one" is the entire question, and counting past
    /// two is work whose answer is never used.
    /// </remarks>
    internal static async Task<TEntity?> FindSingleMatchAsync<TEntity>(IMongoCollection<TEntity> collection, FilterDefinition<TEntity> filter)
        where TEntity : class
    {
        var entities = await collection.Find(filter).Limit(2).ToListAsync();
        return entities.Count == 1 ? entities[0] : null;
    }
}
