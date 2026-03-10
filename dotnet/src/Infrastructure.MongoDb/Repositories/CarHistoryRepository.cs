using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

public class CarHistoryRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<CarHistoryModel, CarHistory>> logger, IMapper mapper)
    : MongoDbRepositoryBase<CarHistoryModel, CarHistory>(mongoDatabase, logger, mapper), ICarHistoryRepository
{
    protected override string CollectionName => "car_history";

    protected override FilterDefinition<CarHistory> GetFilter(string ownerId, string? search, CarHistoryModel input)
    {
        var builder = Builders<CarHistory>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(input.CarId)) filter &= builder.Text(input.CarId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Text(search);
        return filter;
    }
}
