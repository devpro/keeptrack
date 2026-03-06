using System;
using System.Threading.Tasks;
using AutoMapper;
using KeepTrack.Dal.MongoDb.Entities;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Dal.MongoDb.Repositories;

public class CarRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<CarModel, Car>> logger, IMapper mapper)
    : RepositoryBase<CarModel, Car>(mongoDatabase, logger, mapper), ICarRepository
{
    protected override string CollectionName => "car";

    public async Task<CarModel> FindOneAsync(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            throw new ArgumentNullException(nameof(id), $"Cannot find a car. \"{id}\" is not a valid id.");
        }

        var collection = GetCollection();
        var dbEntries = await collection.FindAsync(x => x.Id == id);
        return Mapper.Map<CarModel>(dbEntries.FirstOrDefault());
    }
}
