using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The projections behind Explore's exclusion of what the caller already has:
/// two owner-scoped reads of the caller's collection, and the id lookup over the reference documents they link to.
/// Each is the same query in every domain but for the field it reads, so it is written once here.
/// They are not hooks on <c>MongoDbRepositoryBase</c>, whose entities may have no reference id or title,
/// and passing the field keeps its declaration next to its entity, like <c>SortTitleField</c>.
/// </summary>
internal static class ExploreExclusionQueries
{
    /// <summary>
    /// Every distinct reference document id this owner's items link to.
    /// Linked is the inverse of the repositories' <c>UnresolvedFilter</c>: a real id, neither null nor empty (see docs/data-model.md).
    /// </summary>
    internal static async Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync<TEntity>(
        IMongoCollection<TEntity> collection, string ownerId, Expression<Func<TEntity, string?>> referenceIdField)
        where TEntity : IHasIdAndOwnerId
    {
        var builder = Builders<TEntity>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId)
                     & builder.Ne(referenceIdField, null)
                     & builder.Ne(referenceIdField, string.Empty);
        var ids = await (await collection.DistinctAsync(referenceIdField, filter)).ToListAsync();
        return ids.Where(id => !string.IsNullOrEmpty(id)).Select(id => id!).ToList();
    }

    /// <summary>
    /// The <paramref name="provider"/> id of each given reference, projected server side so only <c>external_ids</c> crosses the wire.
    /// <para>
    /// The caller wants one string per reference, and <c>FindByIdsAsync</c> would fetch whole documents, with synopsis, cast, aliases, ratings and a show's whole episode guide.
    /// A few hundred linked shows would then load every episode of every season on each Explore request.
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

        // a reference resolved through another provider has no id in this one's number space, and contributes nothing rather than an empty string that could match anything
        return externalIds
            .Select(map => map.GetValueOrDefault(provider))
            .Where(externalId => !string.IsNullOrEmpty(externalId))
            .Select(externalId => externalId!)
            .ToList();
    }

    /// <summary>
    /// Every distinct raw title this owner tracks, the caller normalizing them.
    /// The fallback half of the exclusion: an item never linked is invisible to the reference ids, so matching on them alone would keep suggesting what the owner has.
    /// </summary>
    internal static async Task<IReadOnlyList<string>> FindDistinctTitlesAsync<TEntity>(
        IMongoCollection<TEntity> collection, string ownerId, Expression<Func<TEntity, string>> titleField)
        where TEntity : IHasIdAndOwnerId
    {
        var titles = await (await collection.DistinctAsync(titleField, Builders<TEntity>.Filter.Eq(f => f.OwnerId, ownerId))).ToListAsync();
        return titles.Where(title => !string.IsNullOrWhiteSpace(title)).ToList();
    }
}
