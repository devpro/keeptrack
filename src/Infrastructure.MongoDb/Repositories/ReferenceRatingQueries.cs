using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Both ends of the copied reference rating, written once for the five types:
/// the writes and count over the tenant collections, and the projected read of the reference collections feeding them.
/// The tenant fields have the same names everywhere (<see cref="IHasReferenceRating"/>), so no per-domain field expressions are needed.
/// </summary>
internal static class ReferenceRatingQueries
{
    /// <summary>
    /// Stamps the copied rating again on every tenant item linked to <paramref name="referenceId"/>.
    /// <para>
    /// <paramref name="source"/> is written even when <paramref name="rating"/> is null, since it records which source the copy was computed from.
    /// That lets <see cref="CountLinkedOnOtherSourceAsync{TEntity}"/> tell an item on the selected source from one needing a new stamp,
    /// where a null would leave every unrated item looking stale forever.
    /// </para>
    /// </summary>
    internal static async Task<long> SetRatingAsync<TEntity>(
        IMongoCollection<TEntity> collection, string referenceId, double? rating, double? ratingScale, string? source)
        where TEntity : IHasReferenceRating
    {
        var filter = Builders<TEntity>.Filter.Eq(f => f.ReferenceId, referenceId);
        var result = await collection.UpdateManyAsync(filter, RatingUpdate<TEntity>(rating, ratingScale, source));
        return result.ModifiedCount;
    }

    /// <summary>
    /// <see cref="SetRatingAsync{TEntity}"/> for many references, as one unordered bulk write: one round trip per batch rather than per reference.
    /// <para>
    /// That keeps the admin recompute's round trips independent of the number of users.
    /// Each entry is an <c>UpdateMany</c> stamping the items server side, so a reference tracked by one user or by ten thousand costs one operation,
    /// and growth multiplies documents written, never round trips or payload.
    /// Unordered, since the entries are independent, so one failing write does not abandon the rest.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The caller sizes the batch through its paged read, so a second chunking here would only add a knob that has to agree.
    /// The driver still splits an oversized batch into wire-sized chunks.
    /// </remarks>
    internal static async Task<long> SetRatingsAsync<TEntity>(
        IMongoCollection<TEntity> collection,
        IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)> updates)
        where TEntity : IHasReferenceRating
    {
        if (updates.Count == 0) return 0;

        var writes = updates
            .Select(u => new UpdateManyModel<TEntity>(
                Builders<TEntity>.Filter.Eq(f => f.ReferenceId, u.ReferenceId),
                RatingUpdate<TEntity>(u.Rating, u.RatingScale, u.Source)))
            .ToList();

        var result = await collection.BulkWriteAsync(writes, new BulkWriteOptions { IsOrdered = false });
        return result.ModifiedCount;
    }

    // the one place the three copied fields are written, shared by the single and bulk paths, the source always included
    private static UpdateDefinition<TEntity> RatingUpdate<TEntity>(double? rating, double? ratingScale, string? source)
        where TEntity : IHasReferenceRating =>
        Builders<TEntity>.Update
            .Set(f => f.ReferenceRating, rating)
            .Set(f => f.ReferenceRatingScale, ratingScale)
            .Set(f => f.ReferenceRatingSource, source);

    /// <summary>
    /// How many linked items are stamped with something other than <paramref name="source"/>.
    /// <para>
    /// It makes the admin recompute a single count when nothing differs, rather than reading every reference and rewriting values items already hold.
    /// An item never stamped counts as different, so the first recompute backfills it, with no migration script.
    /// </para>
    /// </summary>
    internal static Task<long> CountLinkedOnOtherSourceAsync<TEntity>(IMongoCollection<TEntity> collection, string? source)
        where TEntity : IHasReferenceRating
    {
        var builder = Builders<TEntity>.Filter;
        // linked is the inverse of UnresolvedFilter, a real id neither null nor empty (see docs/data-model.md)
        // Ne also matches a missing or null source, the never-stamped case
        var filter = builder.Ne(f => f.ReferenceId, null)
                     & builder.Ne(f => f.ReferenceId, string.Empty)
                     & builder.Ne(f => f.ReferenceRatingSource, source);
        return collection.CountDocumentsAsync(filter);
    }

    /// <summary>
    /// One page of (id, ratings) from a reference collection, ordered by <c>_id</c> after <paramref name="afterId"/>:
    /// the read half of a recompute, feeding <see cref="SetRatingsAsync{TEntity}"/>.
    /// <para>
    /// Projected, since the recompute reads two fields of large documents, each with a synopsis, a cast and, for TV, a whole episode guide.
    /// Paged by an <c>_id</c> cursor rather than skip and limit, so memory stays bounded and pages never overlap or skip entries.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The generic parameter is unconstrained: reference entities share no interface, but all store <c>ratings</c> under the same element, and the projection has its own type.
    /// <c>afterId</c> is converted to an <see cref="ObjectId"/> first,
    /// since a string id in a field-name filter silently matches nothing, which would look like the end of the collection.
    /// </remarks>
    internal static async Task<IReadOnlyList<(string Id, Dictionary<string, ReferenceRatingModel> Ratings)>> FindRatingsAsync<TEntity>(
        IMongoCollection<TEntity> collection, string? afterId, int limit)
    {
        var filter = string.IsNullOrEmpty(afterId)
            ? Builders<TEntity>.Filter.Empty
            : Builders<TEntity>.Filter.Gt("_id", ObjectId.Parse(afterId));

        var projections = await collection.Find(filter)
            .Sort(Builders<TEntity>.Sort.Ascending("_id"))
            .Limit(limit)
            .Project<RatingsProjection>(Builders<TEntity>.Projection.Include("ratings"))
            .ToListAsync();

        return projections
            .Select(p => (p.Id!, p.Ratings.ToDictionary(
                r => r.Key,
                r => new ReferenceRatingModel { Value = r.Value.Value, Scale = r.Value.Scale, Count = r.Value.Count })))
            .ToList();
    }

    /// <summary>
    /// What <see cref="FindRatingsAsync{TEntity}"/> deserializes into: the two fields a recompute reads.
    /// Not the entity type, since a partial document would leave its <c>required</c> members silently null.
    /// </summary>
    private sealed class RatingsProjection
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("ratings")]
        public Dictionary<string, ReferenceRating> Ratings { get; set; } = [];
    }
}
