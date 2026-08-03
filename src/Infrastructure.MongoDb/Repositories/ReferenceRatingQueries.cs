using System.Threading.Tasks;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The two cross-tenant writes/reads over the denormalized reference rating, written once for all five
/// trackable types - they carry the fields under the same names (<see cref="IHasReferenceRating"/>), so
/// unlike <see cref="ExploreExclusionQueries"/> this needs no per-domain field expressions at all. Each of
/// the five repositories previously held a byte-for-byte copy of the propagation body.
/// </summary>
internal static class ReferenceRatingQueries
{
    /// <summary>
    /// Re-stamps the denormalized rating on every tenant item linked to <paramref name="referenceId"/>.
    /// <para>
    /// <paramref name="source"/> is written even when <paramref name="rating"/> is null: it records which
    /// source the copy was computed from, not where a number came from. A source that simply has no value for
    /// this reference is still the source that was applied, and stamping it is what lets
    /// <see cref="CountLinkedOnOtherSourceAsync{TEntity}"/> tell "already on the selected source" from "still
    /// needs re-stamping" - leaving it null there would make every unrated item look permanently stale.
    /// </para>
    /// </summary>
    internal static async Task<long> SetRatingAsync<TEntity>(
        IMongoCollection<TEntity> collection, string referenceId, double? rating, double? ratingScale, string? source)
        where TEntity : IHasReferenceRating
    {
        var filter = Builders<TEntity>.Filter.Eq(f => f.ReferenceId, referenceId);
        var update = Builders<TEntity>.Update
            .Set(f => f.ReferenceRating, rating)
            .Set(f => f.ReferenceRatingScale, ratingScale)
            .Set(f => f.ReferenceRatingSource, source);
        var result = await collection.UpdateManyAsync(filter, update);
        return result.ModifiedCount;
    }

    /// <summary>
    /// How many linked items are still stamped with something other than <paramref name="source"/>.
    /// <para>
    /// This is what makes the admin's "recompute" a no-op when there is nothing to do: one counted query
    /// instead of reading the whole reference collection and firing an <c>UpdateMany</c> per reference
    /// document, every one of which would set the values they already hold. A never-stamped item (linked
    /// before the source was recorded) counts as mismatched, so the first recompute backfills them and every
    /// later one costs a single count - no migration script needed.
    /// </para>
    /// </summary>
    internal static Task<long> CountLinkedOnOtherSourceAsync<TEntity>(IMongoCollection<TEntity> collection, string? source)
        where TEntity : IHasReferenceRating
    {
        var builder = Builders<TEntity>.Filter;
        // "linked" is the inverse of the repositories' UnresolvedFilter - a real id, neither null nor the
        // legacy empty-string sentinel (see CLAUDE.md). Ne also matches a missing/null source, which is
        // exactly the never-stamped case above.
        var filter = builder.Ne(f => f.ReferenceId, null)
                     & builder.Ne(f => f.ReferenceId, string.Empty)
                     & builder.Ne(f => f.ReferenceRatingSource, source);
        return collection.CountDocumentsAsync(filter);
    }
}
