using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class HouseHistoryRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<HouseHistoryModel, HouseHistory>> logger, IMapper mapper)
    : MongoDbRepositoryBase<HouseHistoryModel, HouseHistory>(mongoDatabase, logger, mapper), IHouseHistoryRepository
{
    protected override string CollectionName => "house_history";

    public async Task<long> DeleteAllForHouseAsync(string houseId, string ownerId)
    {
        var filter = Builders<HouseHistory>.Filter.Eq(f => f.OwnerId, ownerId) & Builders<HouseHistory>.Filter.Eq(f => f.HouseId, houseId);
        var result = await GetCollection().DeleteManyAsync(filter);
        return result.DeletedCount;
    }

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
