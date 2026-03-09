using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

public class CarHistoryMongoDbRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<CarHistoryModel, CarHistory>> logger, IMapper mapper)
    : MongoDbRepositoryBase<CarHistoryModel, CarHistory>(mongoDatabase, logger, mapper), ICarHistoryRepository
{
    protected override string CollectionName => "car_history";

    public async Task<List<CarHistoryModel>> FindAllAsync(string carId, string ownerId)
    {
        var collection = GetCollection();
        var dbEntries = await collection.FindAsync(x => x.CarId == carId && x.OwnerId == ownerId);
        return Mapper.Map<List<CarHistoryModel>>(dbEntries.ToList());
    }
}
