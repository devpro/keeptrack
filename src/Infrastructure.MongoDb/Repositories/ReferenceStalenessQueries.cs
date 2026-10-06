using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// What the periodic sync refreshes next, written once for the five reference collections.
/// </summary>
internal static class ReferenceStalenessQueries
{
    /// <summary>
    /// The stalest <paramref name="limit"/> documents not enriched since <paramref name="cutoff"/>: never enriched first, then least recently enriched.
    /// <para>
    /// Filtering server side avoids loading every reference, each show with its whole episode guide, on every tick.
    /// The ordering makes <paramref name="limit"/> safe: a pass takes the oldest, so what it misses leads the next one.
    /// Unordered, a capped pass would walk the same head of the collection forever and never refresh the tail.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The null half cannot be folded into the comparison: MongoDB compares within a type,
    /// so <c>$lte</c> on a date never matches a null or missing field, and a reference never enriched would never be returned.
    /// <c>Eq(field, null)</c> matches null and missing alike.
    /// Ascending order puts those first, since BSON sorts null ahead of every date.
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
