using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The projections that build the Explore feature's "the caller already has this" exclusion set: two
/// owner-scoped reads over the caller's own collection, plus the id lookup over the shared reference
/// documents those link to. Each is the same query for every domain and differs only by which field it reads,
/// so they live here once rather than being copy-pasted into
/// <c>MovieRepository</c>/<c>TvShowRepository</c>/<c>VideoGameRepository</c> and their reference counterparts
/// (the first two already carried an identical hand-written copy of the reference-id one).
/// They aren't hooks on <c>MongoDbRepositoryBase</c> because that base is generic over entities with no
/// reference id and no title at all - passing the field in keeps the field declaration next to the entity it
/// belongs to, exactly like the <c>SortTitleField</c> hook does for sorting.
/// </summary>
internal static class ExploreExclusionQueries
{
    /// <summary>
    /// Every distinct reference document id this owner's items link to. "Linked" is the inverse of the
    /// repositories' <c>UnresolvedFilter</c>: a real id, neither null nor the legacy empty-string sentinel
    /// (see CLAUDE.md on why an empty string has to be treated as unset here).
    /// </summary>
    internal static async Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync<TEntity>(
        IMongoCollection<TEntity> collection, string ownerId, Expression<Func<TEntity, string?>> referenceIdField)
        where TEntity : IHasIdAndOwnerId
    {
        var builder = Builders<TEntity>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId)
                     & builder.Ne(referenceIdField, null)
                     & builder.Ne(referenceIdField, string.Empty);
        var ids = await collection.Distinct(referenceIdField, filter).ToListAsync();
        return ids.Where(id => !string.IsNullOrEmpty(id)).Select(id => id!).ToList();
    }

    /// <summary>
    /// The <paramref name="provider"/> id of each of the given reference documents, read with a server-side
    /// projection so only <c>external_ids</c> crosses the wire.
    /// <para>
    /// The projection is the whole point. The caller wants exactly one string per reference, and the obvious
    /// <c>FindByIdsAsync</c> would fetch entire documents to get it - synopsis, cast, matched aliases, ratings,
    /// and for TV shows the complete embedded episode guide. An owner tracking a few hundred linked shows
    /// would drag every episode of every season across on each Explore request, to extract a few hundred ids.
    /// </para>
    /// </summary>
    internal static async Task<IReadOnlyList<string>> FindExternalIdsAsync<TEntity>(
        IMongoCollection<TEntity> collection,
        IReadOnlyCollection<string> ids,
        string provider,
        Expression<Func<TEntity, string?>> idField,
        Expression<Func<TEntity, Dictionary<string, string>>> externalIdsField)
    {
        if (ids.Count == 0) return [];

        var externalIds = await collection
            .Find(Builders<TEntity>.Filter.In(idField, ids))
            .Project(externalIdsField)
            .ToListAsync();

        // a reference resolved through a different provider simply has no id in this one's number space -
        // it contributes nothing to the exclusion set rather than an empty string that could match anything.
        return externalIds
            .Select(map => map.GetValueOrDefault(provider))
            .Where(externalId => !string.IsNullOrEmpty(externalId))
            .Select(externalId => externalId!)
            .ToList();
    }

    /// <summary>
    /// Every distinct title this owner tracks, raw (normalization is the caller's job - <c>TitleNormalizer</c>
    /// lives in the layers that compare them, not in a Mongo query). This is the fallback half of the
    /// exclusion set: an item the owner added manually or imported may never have been linked to a reference
    /// document, so matching on the reference id alone would keep suggesting something they already have.
    /// </summary>
    internal static async Task<IReadOnlyList<string>> FindDistinctTitlesAsync<TEntity>(
        IMongoCollection<TEntity> collection, string ownerId, Expression<Func<TEntity, string>> titleField)
        where TEntity : IHasIdAndOwnerId
    {
        var titles = await collection.Distinct(titleField, Builders<TEntity>.Filter.Eq(f => f.OwnerId, ownerId)).ToListAsync();
        return titles.Where(title => !string.IsNullOrWhiteSpace(title)).ToList();
    }
}
