using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class CarRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<CarModel, Car>> logger, IMapper mapper)
    : MongoDbRepositoryBase<CarModel, Car>(mongoDatabase, logger, mapper), ICarRepository
{
    protected override string CollectionName => "car";

    protected override FilterDefinition<Car> GetFilter(string ownerId, string? search, CarModel input)
    {
        var builder = Builders<Car>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Name.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}
