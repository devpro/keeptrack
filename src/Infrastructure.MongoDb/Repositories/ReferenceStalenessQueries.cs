using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The "what should the periodic sync refresh next" query, written once for all five reference collections -
/// they differ only in which entity type carries the timestamp, exactly like
/// <see cref="ExploreExclusionQueries"/>'s per-domain field expressions.
/// </summary>
internal static class ReferenceStalenessQueries
{
    /// <summary>
    /// The stalest <paramref name="limit"/> documents that haven't been enriched since
    /// <paramref name="cutoff"/>, least-recently-enriched first and never-enriched before those.
    /// <para>
    /// Both halves matter. Filtering server-side replaces reading every reference document into memory and
    /// discarding most of them - which for TV meant dragging each show's entire embedded episode guide across
    /// on every tick. And the ordering is what makes <paramref name="limit"/> safe: a pass always takes the
    /// oldest documents, so whatever it doesn't reach is first in line next time. Unordered, a capped pass
    /// would re-walk the same head of the collection forever and the tail would never be refreshed at all.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The null half of the filter cannot be folded into the comparison: MongoDB compares within a type, so
    /// <c>$lte</c> against a date never matches a null or absent field, and a reference that has never been
    /// enriched - the one most in need of a pass - would be the one document the query could never return.
    /// <c>Eq(field, null)</c> matches both null and missing, which is also what covers documents written
    /// before the field existed. Ascending order then puts those first for free: BSON sorts null ahead of
    /// every date.
    /// </remarks>
    internal static Task<List<TEntity>> FindStaleAsync<TEntity>(
        IMongoCollection<TEntity> collection,
        Expression<Func<TEntity, DateTime?>> lastEnrichedAt,
        DateTime cutoff,
        int limit)
    {
        var builder = Builders<TEntity>.Filter;
        var filter = builder.Eq(lastEnrichedAt, null) | builder.Lte(lastEnrichedAt, cutoff);

        return collection.Find(filter)
            .Sort(Builders<TEntity>.Sort.Ascending(new ExpressionFieldDefinition<TEntity, DateTime?>(lastEnrichedAt)))
            .Limit(limit)
            .ToListAsync();
    }
}
