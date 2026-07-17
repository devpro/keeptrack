using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class HealthProfileRepository(IMongoDatabase mongoDatabase, ILogger<HealthProfileRepository> logger, IStorageMapper<HealthProfileModel, HealthProfile> mapper)
    : MongoDbRepositoryBase<HealthProfileModel, HealthProfile>(mongoDatabase, logger, mapper), IHealthProfileRepository
{
    protected override string CollectionName => "health_profile";

    protected override FilterDefinition<HealthProfile> GetFilter(string ownerId, string? search, HealthProfileModel input)
    {
        var builder = Builders<HealthProfile>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Name.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}
