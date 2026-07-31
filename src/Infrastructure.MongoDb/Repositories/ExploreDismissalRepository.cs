using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Persistence for Explore dismissals. Reads only ever project the external id (via <c>Distinct</c>) and
/// writes only ever set the natural-key fields, so this needs no full model &lt;-&gt; entity mapper.
/// </summary>
public class ExploreDismissalRepository(IMongoDatabase mongoDatabase) : IExploreDismissalRepository
{
    private const string CollectionName = "explore_dismissal";

    private IMongoCollection<ExploreDismissal> Collection => mongoDatabase.GetCollection<ExploreDismissal>(CollectionName);

    public async Task<IReadOnlyList<string>> FindDismissedExternalIdsAsync(string ownerId, ExploreItemType type, string externalSource) =>
        await Collection.Distinct(d => d.ExternalId, KeyFilter(ownerId, type, externalSource)).ToListAsync();

    public async Task AddAsync(ExploreDismissalModel model)
    {
        var filter = KeyFilter(model.OwnerId, model.ItemType, model.ExternalSource)
                     & Builders<ExploreDismissal>.Filter.Eq(d => d.ExternalId, model.ExternalId);
        // SetOnInsert-only upsert: inserts the record when missing, a no-op when it already exists - so
        // dismissing the same suggestion twice never creates a duplicate row.
        var update = Builders<ExploreDismissal>.Update
            .SetOnInsert(d => d.OwnerId, model.OwnerId)
            .SetOnInsert(d => d.ItemType, model.ItemType)
            .SetOnInsert(d => d.ExternalSource, model.ExternalSource)
            .SetOnInsert(d => d.ExternalId, model.ExternalId);
        await Collection.UpdateOneAsync(filter, update, new UpdateOptions { IsUpsert = true });
    }

    public async Task RemoveAsync(string ownerId, ExploreItemType type, string externalSource, string externalId) =>
        await Collection.DeleteOneAsync(
            KeyFilter(ownerId, type, externalSource) & Builders<ExploreDismissal>.Filter.Eq(d => d.ExternalId, externalId));

    // the (owner, domain, provider) prefix of the natural key - shared by every read and write so the three
    // never drift on what a dismissal is scoped to.
    private static FilterDefinition<ExploreDismissal> KeyFilter(string ownerId, ExploreItemType type, string externalSource) =>
        Builders<ExploreDismissal>.Filter.Eq(d => d.OwnerId, ownerId)
        & Builders<ExploreDismissal>.Filter.Eq(d => d.ItemType, type)
        & Builders<ExploreDismissal>.Filter.Eq(d => d.ExternalSource, externalSource);
}
