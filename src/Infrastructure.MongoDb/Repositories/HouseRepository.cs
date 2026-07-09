using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class HouseRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<HouseModel, House>> logger, IMapper mapper)
    : MongoDbRepositoryBase<HouseModel, House>(mongoDatabase, logger, mapper), IHouseRepository
{
    protected override string CollectionName => "house";

    protected override FilterDefinition<House> GetFilter(string ownerId, string? search, HouseModel input)
    {
        var builder = Builders<House>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Name.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}
