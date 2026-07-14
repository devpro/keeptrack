using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class CarHistoryRepository(IMongoDatabase mongoDatabase, ILogger<CarHistoryRepository> logger, IStorageMapper<CarHistoryModel, CarHistory> mapper)
    : MongoDbRepositoryBase<CarHistoryModel, CarHistory>(mongoDatabase, logger, mapper), ICarHistoryRepository
{
    protected override string CollectionName => "car_history";

    public async Task<long> DeleteAllForCarAsync(string carId, string ownerId)
    {
        var filter = Builders<CarHistory>.Filter.Eq(f => f.OwnerId, ownerId) & Builders<CarHistory>.Filter.Eq(f => f.CarId, carId);
        var result = await GetCollection().DeleteManyAsync(filter);
        return result.DeletedCount;
    }

    protected override FilterDefinition<CarHistory> GetFilter(string ownerId, string? search, CarHistoryModel input)
    {
        var builder = Builders<CarHistory>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(input.CarId)) filter &= builder.Eq(f => f.CarId, input.CarId);
        if (!string.IsNullOrEmpty(search))
        {
            filter &= builder.Where(f => f.Description != null
                                          && f.Description.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        }
        return filter;
    }
}
