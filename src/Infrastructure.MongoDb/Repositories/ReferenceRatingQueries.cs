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
/// Both ends of the denormalized reference rating, written once for all five trackable types: the
/// cross-tenant writes/count over the tenant collections, and the projected read of the reference
/// collections that feeds them. The tenant side carries its fields under the same names everywhere
/// (<see cref="IHasReferenceRating"/>), so unlike <see cref="ExploreExclusionQueries"/> this needs no
/// per-domain field expressions at all. Each of the five repositories previously held a byte-for-byte copy
/// of the propagation body.
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
        var result = await collection.UpdateManyAsync(filter, RatingUpdate<TEntity>(rating, ratingScale, source));
        return result.ModifiedCount;
    }

    /// <summary>
    /// The same re-stamp as <see cref="SetRatingAsync{TEntity}"/> for many references at once, as a single
    /// unordered bulk write - one round trip for the whole batch instead of one per reference.
    /// <para>
    /// This is what keeps the admin recompute's cost independent of how many users there are. Each entry is
    /// still an <c>UpdateMany</c>, so the items themselves are re-stamped server-side: a reference tracked by
    /// one user and a reference tracked by ten thousand cost the same single operation to propagate, and
    /// growth multiplies documents written, never round trips or payload. Unordered because the entries are
    /// independent per reference - one failing write must not abandon the rest of the batch, the same reason
    /// <see cref="ExploreCatalogueRepository.UpsertManyAsync"/> is unordered.
    /// </para>
    /// </summary>
    /// <remarks>
    /// Batching is the caller's business (see the recompute loop's page size), not this method's: the read
    /// that produces these updates is already paged, so adding a second chunking mechanism here would only
    /// give two knobs that have to agree. The driver still splits an oversized batch into wire-sized chunks
    /// on its own.
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

    // the one place the three denormalized fields are written, shared by the single and bulk paths so they
    // can never disagree about what a re-stamp sets (notably: the source, always, value or no value).
    private static UpdateDefinition<TEntity> RatingUpdate<TEntity>(double? rating, double? ratingScale, string? source)
        where TEntity : IHasReferenceRating =>
        Builders<TEntity>.Update
            .Set(f => f.ReferenceRating, rating)
            .Set(f => f.ReferenceRatingScale, ratingScale)
            .Set(f => f.ReferenceRatingSource, source);

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

    /// <summary>
    /// One page of (id, ratings) from a *reference* collection, ordered by <c>_id</c> and starting after
    /// <paramref name="afterId"/> - the read half of a recompute, feeding
    /// <see cref="SetRatingsAsync{TEntity}"/>.
    /// <para>
    /// Projected, because the recompute wants two fields and the documents are anything but small: reading
    /// whole reference documents to get at <c>ratings</c> drags every synopsis, every cast list and - for TV -
    /// each show's entire embedded episode guide across the wire, exactly the waste
    /// <see cref="ExploreExclusionQueries.FindExternalIdsAsync"/> and <see cref="ReferenceStalenessQueries"/>
    /// were written to stop. Paged by an <c>_id</c> cursor rather than skip/limit so memory stays bounded
    /// however large the collection grows, and so pages can't overlap or skip entries the way a shifting
    /// skip does.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The generic parameter is unconstrained: reference entities share no interface (they are five
    /// independent shapes), but they do all store their ratings under the same <c>ratings</c> element, and
    /// the projection is deserialized into its own type rather than the entity - so nothing here needs to
    /// know which collection it is reading. <c>afterId</c> is converted to an <see cref="ObjectId"/> before
    /// it is compared: a string-field-name filter holding a plain string id matches nothing, silently (see
    /// <c>DatabaseTestBase.TrackDocument</c>) - which here would look like a collection that simply ended.
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
    /// What <see cref="FindRatingsAsync{TEntity}"/> deserializes into: the two fields a recompute reads, from
    /// whichever of the five reference collections it was pointed at. Deliberately not the entity type -
    /// deserializing a deliberately partial document into one would leave its <c>required</c> members
    /// silently null, producing something that claims to be a reference document and isn't.
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
