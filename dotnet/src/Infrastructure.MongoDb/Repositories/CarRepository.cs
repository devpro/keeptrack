using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

public class CarRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<CarModel, Car>> logger, IMapper mapper)
    : MongoDbRepositoryBase<CarModel, Car>(mongoDatabase, logger, mapper), ICarRepository
{
    protected override string CollectionName => "car";
}
