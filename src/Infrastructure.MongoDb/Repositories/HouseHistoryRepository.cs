using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class HouseHistoryRepository(IMongoDatabase mongoDatabase, ILogger<HouseHistoryRepository> logger, IStorageMapper<HouseHistoryModel, HouseHistory> mapper)
    : MongoDbRepositoryBase<HouseHistoryModel, HouseHistory>(mongoDatabase, logger, mapper), IHouseHistoryRepository
{
    protected override string CollectionName => "house_history";

    public Task<long> DeleteAllForHouseAsync(string houseId, string ownerId)
        => DeleteAllByParentAsync(f => f.HouseId, houseId, ownerId);

    protected override FilterDefinition<HouseHistory> GetFilter(string ownerId, string? search, HouseHistoryModel input)
    {
        var builder = Builders<HouseHistory>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(input.HouseId)) filter &= builder.Eq(f => f.HouseId, input.HouseId);
        if (!string.IsNullOrEmpty(search))
        {
            filter &= builder.Where(f => f.Description != null
                                          && f.Description.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        }
        return filter;
    }
}
