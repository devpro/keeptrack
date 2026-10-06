using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// One document per (provider, UTC day), reserved with one atomic upsert.
/// The filter matches only while the day's count is below the caller's ceiling, so a spent allowance turns the upsert into an insert colliding on _id.
/// The uniqueness of _id holds the ceiling across replicas, like <see cref="LeaseRepository"/>,
/// with no transaction and no race where two replicas both see "999 used" and spend the last call.
/// </summary>
public class ProviderQuotaRepository(IMongoDatabase mongoDatabase) : IProviderQuotaRepository
{
    private const string CollectionName = "provider_quota";

    private IMongoCollection<ProviderQuota> Collection => mongoDatabase.GetCollection<ProviderQuota>(CollectionName);

    public async Task<bool> TryConsumeAsync(string provider, DateOnly day, int ceiling, CancellationToken cancellationToken = default)
    {
        // a ceiling of zero or less means no allowance (the whole budget is reserved for higher-priority work), so nothing is spent or created
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
            // the day's document is at the ceiling: the filter matched nothing,
            // so the upsert tried a second document with the same _id, and that collision means the allowance is spent
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
        // $max rather than $set: another replica may already have pushed the count past the total, and lowering it would hand out calls the provider just refused
        var update = Builders<ProviderQuota>.Update
            .Max(q => q.Used, total)
            .SetOnInsert(q => q.CreatedAt, DateTime.UtcNow);

        try
        {
            await Collection.UpdateOneAsync(q => q.Id == Key(provider, day), update, new UpdateOptions { IsUpsert = true }, cancellationToken);
        }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            // another replica inserted the day's document between this upsert's match and insert, so the update now applies as a plain one
            await Collection.UpdateOneAsync(q => q.Id == Key(provider, day), update, cancellationToken: cancellationToken);
        }
    }

    /// <summary>
    /// The natural key, shared by every operation so they agree on the counter they touch.
    /// The date is formatted invariantly, so a server under a non-Gregorian culture produces the same key as its peers.
    /// </summary>
    private static string Key(string provider, DateOnly day) =>
        $"{provider}:{day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";
}
