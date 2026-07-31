using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The two owner-scoped projections that build the Explore feature's "the caller already has this" exclusion
/// set. Both are the same query for every domain and differ only by which field they read, so they live here
/// once rather than being copy-pasted into <c>MovieRepository</c>/<c>TvShowRepository</c>/<c>VideoGameRepository</c>
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
