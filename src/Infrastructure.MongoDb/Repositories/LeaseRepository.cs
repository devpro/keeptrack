using System;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// One document per lease name, acquired with one atomic upsert.
/// The filter matches only an expired lease or one already held by the caller, so a live lease held by another turns the upsert into an insert colliding on _id.
/// The uniqueness of _id is the mutual exclusion, with no transaction or extra index.
/// </summary>
public class LeaseRepository(IMongoDatabase mongoDatabase) : ILeaseRepository
{
    private const string CollectionName = "lease";

    private IMongoCollection<Lease> Collection => mongoDatabase.GetCollection<Lease>(CollectionName);

    public async Task<bool> TryAcquireAsync(string name, string holderId, TimeSpan duration)
    {
        var now = DateTime.UtcNow;
        var builder = Builders<Lease>.Filter;
        var expiredOrOurs = builder.Eq(l => l.Id, name)
                            & (builder.Lt(l => l.ExpiresAt, now) | builder.Eq(l => l.Holder, holderId));
        var update = Builders<Lease>.Update
            .Set(l => l.Holder, holderId)
            .Set(l => l.ExpiresAt, now + duration);

        try
        {
            var result = await Collection.UpdateOneAsync(expiredOrOurs, update, new UpdateOptions { IsUpsert = true });
            return result.MatchedCount > 0 || result.UpsertedId is not null;
        }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // the lease is live under another holder: the filter matched nothing, so the upsert tried to insert a second document with the same _id
            return false;
        }
    }

    public async Task<LeaseModel?> FindAsync(string name)
    {
        var entity = await Collection.Find(l => l.Id == name).FirstOrDefaultAsync();
        // mapped by hand, since a three-field read-only diagnostic does not warrant a generated mapper
        return entity is null ? null : new LeaseModel { Name = entity.Id, Holder = entity.Holder, ExpiresAt = entity.ExpiresAt };
    }
}
