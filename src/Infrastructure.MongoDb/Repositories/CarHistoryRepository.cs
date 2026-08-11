using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class CarHistoryRepository(IMongoDatabase mongoDatabase, ILogger<CarHistoryRepository> logger, IStorageMapper<CarHistoryModel, CarHistory> mapper)
    : MongoDbRepositoryBase<CarHistoryModel, CarHistory>(mongoDatabase, logger, mapper), ICarHistoryRepository
{
    protected override string CollectionName => "car_history";

    public Task<long> DeleteAllForCarAsync(string carId, string ownerId)
        => DeleteAllByParentAsync(f => f.CarId, carId, ownerId);

    public Task<IReadOnlyList<string>> FindDistinctFuelCategoriesAsync(string ownerId)
        => FindDistinctValuesAsync(f => f.Fuel!.Category, ownerId);

    /// <summary>
    /// Not owner-scoped, unlike everything else here: <c>car_station</c> is shared, so "is this station
    /// still in use" has to mean "by anyone", or an admin would delete a station out from under another
    /// tenant's entries.
    /// </summary>
    public Task<long> CountUsingStationAsync(string stationId)
    {
        if (!ObjectId.TryParse(stationId, out _)) return Task.FromResult(0L);
        return GetCollection().CountDocumentsAsync(Builders<CarHistory>.Filter.Eq(f => f.StationId, stationId));
    }

    public async Task<Dictionary<string, long>> CountByStationAsync()
    {
        var results = await GetCollection().Aggregate()
            .Match(Builders<CarHistory>.Filter.Ne(f => f.StationId, null))
            .Group(f => f.StationId, g => new { StationId = g.Key, Count = g.Count() })
            .ToListAsync();
        return results
            .Where(x => !string.IsNullOrEmpty(x.StationId))
            .ToDictionary(x => x.StationId!, x => (long)x.Count);
    }

    public async Task<long> RepointStationAsync(string fromStationId, string toStationId)
    {
        if (!ObjectId.TryParse(fromStationId, out _) || !ObjectId.TryParse(toStationId, out _)) return 0;
        var result = await GetCollection().UpdateManyAsync(
            Builders<CarHistory>.Filter.Eq(f => f.StationId, fromStationId),
            Builders<CarHistory>.Update.Set(f => f.StationId, toStationId));
        return result.ModifiedCount;
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
