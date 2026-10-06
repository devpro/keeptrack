using System.Collections.Generic;
using System.Threading;
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

    public Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId, CancellationToken cancellationToken = default)
        => DeleteAllByParentAsync(f => f.HealthProfileId, healthProfileId, ownerId, cancellationToken);

    public Task<IReadOnlyList<string>> FindDistinctSpecialtiesAsync(string ownerId)
        => FindDistinctValuesAsync(f => f.Specialty, ownerId);

    public Task<IReadOnlyList<string>> FindDistinctPractitionersAsync(string ownerId)
        => FindDistinctValuesAsync(f => f.Practitioner, ownerId);

    protected override FilterDefinition<HealthRecord> GetFilter(string ownerId, string? search, HealthRecordModel input)
    {
        var builder = Builders<HealthRecord>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        // the parent id is filtered with Eq, never Text, since MongoDB allows one $text per query (see docs/data-model.md's Search section)
        if (!string.IsNullOrEmpty(input.HealthProfileId)) filter &= builder.Eq(f => f.HealthProfileId, input.HealthProfileId);
        if (!string.IsNullOrEmpty(search))
        {
            // a search spans the three identifying free-text fields, like a book's title, series and author
            filter &= builder.Where(f => (f.Description != null && f.Description.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                          || (f.Practitioner != null && f.Practitioner.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                          || (f.Specialty != null && f.Specialty.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)));
        }
        return filter;
    }
}
