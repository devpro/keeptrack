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
}
