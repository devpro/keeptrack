using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Hand-written rather than a Mapperly <c>[Mapper]</c> class for the same reason
/// <see cref="CarHistoryStorageMapper"/> is: the model's flat Longitude/Latitude pair fans out into the
/// entity's <c>[longitude, latitude]</c> coordinates array and back.
/// </summary>
public class CarStationStorageMapper : IStorageMapper<CarStationModel, CarStation>
{
    public CarStation ToEntity(CarStationModel model)
    {
        return new CarStation
        {
            Id = model.Id,
            BrandName = model.BrandName,
            City = model.City,
            PostalCode = model.PostalCode,
            Country = model.Country,
            // never persist an empty list, only a real 2-element [lon, lat] pair or nothing - the read
            // side indexes Coordinates[0]/[1] guarded by "!= null", which an empty list would defeat.
            // Same contract as CarHistoryStorageMapper.BuildLocation.
            Coordinates = model.Longitude.HasValue && model.Latitude.HasValue
                ? [model.Longitude.Value, model.Latitude.Value]
                : null,
            BrandNameNormalized = model.BrandNameNormalized,
            CityNormalized = model.CityNormalized,
        };
    }

    public CarStationModel ToModel(CarStation entity)
    {
        return new CarStationModel
        {
            Id = entity.Id,
            BrandName = entity.BrandName,
            City = entity.City,
            PostalCode = entity.PostalCode,
            Country = entity.Country,
            Longitude = entity.Coordinates != null ? entity.Coordinates[0] : null,
            Latitude = entity.Coordinates != null ? entity.Coordinates[1] : null,
            BrandNameNormalized = entity.BrandNameNormalized,
            CityNormalized = entity.CityNormalized,
        };
    }

    public List<CarStationModel> ToModels(List<CarStation> entities)
    {
        var models = new List<CarStationModel>(entities.Count);
        foreach (var entity in entities) models.Add(ToModel(entity));
        return models;
    }
}
