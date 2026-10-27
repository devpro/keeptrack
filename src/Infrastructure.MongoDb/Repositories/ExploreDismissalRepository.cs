using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Persistence for Explore dismissals.
/// Reads only project the external id (<c>Distinct</c>) and writes only set the natural-key fields, so no mapper is needed.
/// </summary>
public class ExploreDismissalRepository(IMongoDatabase mongoDatabase) : IExploreDismissalRepository
{
    private const string CollectionName = "explore_dismissal";

    private IMongoCollection<ExploreDismissal> Collection => mongoDatabase.GetCollection<ExploreDismissal>(CollectionName);

    public async Task<IReadOnlyList<string>> FindDismissedExternalIdsAsync(string ownerId, ExploreItemType type, string externalSource) =>
        await (await Collection.DistinctAsync(d => d.ExternalId, KeyFilter(ownerId, type, externalSource))).ToListAsync();

    public async Task AddAsync(ExploreDismissalModel model)
    {
        var filter = KeyFilter(model.OwnerId, model.ItemType, model.ExternalSource)
                     & Builders<ExploreDismissal>.Filter.Eq(d => d.ExternalId, model.ExternalId);
        // an upsert setting fields on insert only, so dismissing twice never creates a duplicate
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

    // the (owner, domain, provider) prefix of the natural key, shared by every read and write
    private static FilterDefinition<ExploreDismissal> KeyFilter(string ownerId, ExploreItemType type, string externalSource) =>
        Builders<ExploreDismissal>.Filter.Eq(d => d.OwnerId, ownerId)
        & Builders<ExploreDismissal>.Filter.Eq(d => d.ItemType, type)
        & Builders<ExploreDismissal>.Filter.Eq(d => d.ExternalSource, externalSource);
}
