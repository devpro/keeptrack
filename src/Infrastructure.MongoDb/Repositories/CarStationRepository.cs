using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// Purpose-built repository for the shared, owner-less <c>car_station</c> collection - it deliberately
/// doesn't extend <see cref="MongoDbRepositoryBase{TModel, TEntity}"/>, which is hard-constrained to
/// owner-scoped paged CRUD, the same way the <c>*_reference</c> repositories don't.
/// </summary>
public class CarStationRepository(IMongoDatabase mongoDatabase, IStorageMapper<CarStationModel, CarStation> mapper)
    : ICarStationRepository
{
    private const string CollectionName = "car_station";

    private IMongoCollection<CarStation> Collection => mongoDatabase.GetCollection<CarStation>(CollectionName);

    public async Task<CarStationModel?> FindByIdAsync(string id)
    {
        // an id that isn't a valid ObjectId names no document rather than raising FormatException from the
        // driver's ObjectId.Parse - same contract as MongoDbRepositoryBase.FindOneAsync
        if (!ObjectId.TryParse(id, out _)) return null;
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // Find can legitimately match nothing, and the mapper throws on a null source
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<CarStationModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        var valid = ids.Where(id => ObjectId.TryParse(id, out _)).ToList();
        if (valid.Count == 0) return [];
        var entities = await Collection.Find(Builders<CarStation>.Filter.In(x => x.Id, valid)).ToListAsync();
        return mapper.ToModels(entities);
    }

    public async Task<List<CarStationModel>> FindAllAsync()
    {
        var entities = await Collection
            .Find(FilterDefinition<CarStation>.Empty)
            .Sort(Builders<CarStation>.Sort.Ascending(x => x.BrandNameNormalized).Ascending(x => x.CityNormalized))
            .ToListAsync();
        return mapper.ToModels(entities);
    }

    public async Task<CarStationModel?> FindByNaturalKeyAsync(string brandName, string? city, string? postalCode)
    {
        var builder = Builders<CarStation>.Filter;
        var filter = builder.Eq(x => x.BrandNameNormalized, TitleNormalizer.Normalize(brandName))
                     & builder.Eq(x => x.CityNormalized, NormalizeCity(city))
                     & builder.Eq(x => x.PostalCode, NormalizeOptional(postalCode));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<CarStationModel> UpsertAsync(CarStationModel model)
    {
        model.BrandName = model.BrandName.Trim();
        model.City = NormalizeOptional(model.City);
        model.PostalCode = NormalizeOptional(model.PostalCode);
        model.Country = NormalizeOptional(model.Country);
        model.BrandNameNormalized = TitleNormalizer.Normalize(model.BrandName);
        model.CityNormalized = NormalizeCity(model.City);

        var entity = mapper.ToEntity(model);
        if (string.IsNullOrEmpty(entity.Id))
        {
            await Collection.InsertOneAsync(entity);
            model.Id = entity.Id;
            return model;
        }

        await Collection.ReplaceOneAsync(x => x.Id == entity.Id, entity);
        return model;
    }

    public async Task<bool> DeleteAsync(string id)
    {
        if (!ObjectId.TryParse(id, out _)) return false;
        var result = await Collection.DeleteOneAsync(x => x.Id == id);
        return result.DeletedCount > 0;
    }

    /// <summary>
    /// A missing city is part of the natural key, so it has to normalize to a value the index can compare -
    /// an empty string, never null. A key field that is sometimes null and sometimes "" is the same
    /// null-or-empty trap <c>TvShowRepository.UnresolvedFilter</c> exists for, and here it would let two
    /// documents share a key the unique index was supposed to reject.
    /// </summary>
    private static string NormalizeCity(string? city) => string.IsNullOrWhiteSpace(city) ? "" : TitleNormalizer.Normalize(city);

    private static string? NormalizeOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
