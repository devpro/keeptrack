using System;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// One document per lease name, acquired with a single atomic upsert: the filter only matches when the
/// lease is expired or already ours, so a live lease held by someone else makes the upsert attempt an
/// insert that collides with the existing _id - MongoDB's own uniqueness on _id is the mutual exclusion,
/// no transaction or extra index needed.
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
            // the lease exists and is live under another holder: the filter matched nothing, so the
            // upsert tried to insert a second document with the same _id
            return false;
        }
    }

    public async Task<LeaseModel?> FindAsync(string name)
    {
        var entity = await Collection.Find(l => l.Id == name).FirstOrDefaultAsync();
        // hand-mapped: a three-field read-only diagnostic projection with no evolving entity pair to
        // drift-check doesn't warrant a generated mapper
        return entity is null ? null : new LeaseModel { Name = entity.Id, Holder = entity.Holder, ExpiresAt = entity.ExpiresAt };
    }
}
