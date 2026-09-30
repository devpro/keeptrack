using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// One document per (provider, UTC day), reserved with a single atomic upsert: the filter matches only while
/// the day's count is still below the caller's ceiling, so a full allowance turns the upsert into an insert
/// that collides with the existing _id - MongoDB's own _id uniqueness is what makes the ceiling hold across
/// replicas, exactly like <see cref="LeaseRepository"/>'s mutual exclusion. No transaction, no extra index,
/// and no read-then-write race where two replicas both see "999 used" and both spend the last call.
/// </summary>
public class ProviderQuotaRepository(IMongoDatabase mongoDatabase) : IProviderQuotaRepository
{
    private const string CollectionName = "provider_quota";

    private IMongoCollection<ProviderQuota> Collection => mongoDatabase.GetCollection<ProviderQuota>(CollectionName);

    public async Task<bool> TryConsumeAsync(string provider, DateOnly day, int ceiling, CancellationToken cancellationToken = default)
    {
        // a non-positive ceiling means the caller has no allowance at all (e.g. the whole budget is reserved
        // for higher-priority work) - never spend, and never create a document for it either
        if (ceiling <= 0) return false;

        var builder = Builders<ProviderQuota>.Filter;
        var underCeiling = builder.Eq(q => q.Id, Key(provider, day)) & builder.Lt(q => q.Used, ceiling);
        var update = Builders<ProviderQuota>.Update
            .Inc(q => q.Used, 1)
            .SetOnInsert(q => q.CreatedAt, DateTime.UtcNow);

        try
        {
            var result = await Collection.UpdateOneAsync(underCeiling, update, new UpdateOptions { IsUpsert = true }, cancellationToken);
            return result.MatchedCount > 0 || result.UpsertedId is not null;
        }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // the day's document exists and is already at (or above) the ceiling: the filter matched nothing,
            // so the upsert tried to insert a second document with the same _id. That collision *is* the
            // answer - the allowance is spent.
            return false;
        }
    }

    public async Task<int> GetUsedAsync(string provider, DateOnly day, CancellationToken cancellationToken = default)
    {
        var entity = await Collection.Find(q => q.Id == Key(provider, day)).FirstOrDefaultAsync(cancellationToken);
        return entity?.Used ?? 0;
    }

    public async Task ExhaustAsync(string provider, DateOnly day, int total, CancellationToken cancellationToken = default)
    {
        // $max, never a plain $set: a concurrent replica may have pushed the count past `total` already, and
        // lowering it would hand out calls the provider has just told us don't exist.
        var update = Builders<ProviderQuota>.Update
            .Max(q => q.Used, total)
            .SetOnInsert(q => q.CreatedAt, DateTime.UtcNow);

        try
        {
            await Collection.UpdateOneAsync(q => q.Id == Key(provider, day), update, new UpdateOptions { IsUpsert = true }, cancellationToken);
        }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // another replica inserted the day's document between this upsert's own match and insert - the
            // document now exists, so the same update applies cleanly as a plain update
            await Collection.UpdateOneAsync(q => q.Id == Key(provider, day), update, cancellationToken: cancellationToken);
        }
    }

    /// <summary>
    /// The natural key, shared by every operation so a reservation, a read and an exhaust can never disagree
    /// about which counter they're touching. The date is formatted invariantly - a server running under a
    /// non-Gregorian culture must still produce the same key as its peers.
    /// </summary>
    private static string Key(string provider, DateOnly day) =>
        $"{provider}:{day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";
}
