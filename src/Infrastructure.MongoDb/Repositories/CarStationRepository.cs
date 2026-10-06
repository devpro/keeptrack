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
/// Repository for the shared <c>car_station</c> collection.
/// Like the <c>*_reference</c> repositories, it does not extend <see cref="MongoDbRepositoryBase{TModel, TEntity}"/>, which is constrained to owner-scoped paged CRUD.
/// </summary>
public class CarStationRepository(IMongoDatabase mongoDatabase, IStorageMapper<CarStationModel, CarStation> mapper)
    : ICarStationRepository
{
    private const string CollectionName = "car_station";

    private IMongoCollection<CarStation> Collection => mongoDatabase.GetCollection<CarStation>(CollectionName);

    public async Task<CarStationModel?> FindByIdAsync(string id)
    {
        // an invalid ObjectId names no document, rather than the driver throwing FormatException, as in MongoDbRepositoryBase.FindOneAsync
        if (!ObjectId.TryParse(id, out _)) return null;
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        // the mapper throws on a null source, so a missing document is checked first
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
    /// A missing city is part of the natural key, so it normalizes to a value the index compares: an empty string, never null.
    /// A key field sometimes null and sometimes "" would let two documents share a key the unique index should reject.
    /// </summary>
    private static string NormalizeCity(string? city) => string.IsNullOrWhiteSpace(city) ? "" : TitleNormalizer.Normalize(city);

    private static string? NormalizeOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
