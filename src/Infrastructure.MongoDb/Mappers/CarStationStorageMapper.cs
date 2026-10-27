using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Hand-written like <see cref="CarHistoryStorageMapper"/>: the model's flat longitude and latitude fan out into the entity's <c>[longitude, latitude]</c> array and back.
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
            // a real [lon, lat] pair or nothing, as in CarHistoryStorageMapper.BuildLocation
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
