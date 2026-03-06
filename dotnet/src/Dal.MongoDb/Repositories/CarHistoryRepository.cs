using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using KeepTrack.Dal.MongoDb.Entities;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Dal.MongoDb.Repositories;

public class CarHistoryRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<CarHistoryModel, CarHistory>> logger, IMapper mapper)
    : RepositoryBase<CarHistoryModel, CarHistory>(mongoDatabase, logger, mapper), ICarHistoryRepository
{
    protected override string CollectionName => "car_history";

    public async Task<List<CarHistoryModel>> FindAllAsync(string carId, string ownerId)
    {
        var collection = GetCollection();
        var dbEntries = await collection.FindAsync(x => x.CarId == carId && x.OwnerId == ownerId);
        return Mapper.Map<List<CarHistoryModel>>(dbEntries.ToList());
    }
}
