using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class HealthRecordRepository(IMongoDatabase mongoDatabase, ILogger<HealthRecordRepository> logger, IStorageMapper<HealthRecordModel, HealthRecord> mapper)
    : MongoDbRepositoryBase<HealthRecordModel, HealthRecord>(mongoDatabase, logger, mapper), IHealthRecordRepository
{
    protected override string CollectionName => "health_record";

    public async Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId)
    {
        var filter = Builders<HealthRecord>.Filter.Eq(f => f.OwnerId, ownerId) & Builders<HealthRecord>.Filter.Eq(f => f.HealthProfileId, healthProfileId);
        var result = await GetCollection().DeleteManyAsync(filter);
        return result.DeletedCount;
    }

    protected override FilterDefinition<HealthRecord> GetFilter(string ownerId, string? search, HealthRecordModel input)
    {
        var builder = Builders<HealthRecord>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        // parent-id filter with Eq, never Text - see CLAUDE.md's CarHistory gotcha
        if (!string.IsNullOrEmpty(input.HealthProfileId)) filter &= builder.Eq(f => f.HealthProfileId, input.HealthProfileId);
        if (!string.IsNullOrEmpty(search))
        {
            // "who/what was that" searches span the three identifying free-text fields, like Book's
            // title/series/author triple
            filter &= builder.Where(f => (f.Description != null && f.Description.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                          || (f.Practitioner != null && f.Practitioner.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                          || (f.Specialty != null && f.Specialty.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)));
        }
        return filter;
    }
}
