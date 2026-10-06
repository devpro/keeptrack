using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Hand-written rather than a Mapperly <c>[Mapper]</c>: the model's flat location and fuel fields fan out into the entity's Location and Fuel sub-documents and back, which reads better as plain C# than as attributes.
/// </summary>
public class CarHistoryStorageMapper : IStorageMapper<CarHistoryModel, CarHistory>
{
    public CarHistory ToEntity(CarHistoryModel model)
    {
        return new CarHistory
        {
            Id = model.Id,
            OwnerId = model.OwnerId,
            CarId = model.CarId,
            // a full DateTime on both sides, so nothing upstream stamps DateTimeKind.Utc, which the driver's DateTimeSerializer requires
            HistoryDate = DateTime.SpecifyKind(model.HistoryDate, DateTimeKind.Utc),
            Mileage = model.Mileage,
            EventType = model.EventType,
            Description = model.Description,
            Cost = model.Cost,
            Location = BuildLocation(model),
            Fuel = BuildFuel(model),
            StationId = string.IsNullOrWhiteSpace(model.StationId) ? null : model.StationId,
            Garage = model.Garage,
        };
    }

    public CarHistoryModel ToModel(CarHistory entity)
    {
        return new CarHistoryModel
        {
            Id = entity.Id,
            OwnerId = entity.OwnerId,
            CarId = entity.CarId,
            HistoryDate = entity.HistoryDate,
            Mileage = (int?)entity.Mileage,
            EventType = entity.EventType,
            Description = entity.Description,
            Cost = entity.Cost,
            City = entity.Location?.City,
            PostalCode = entity.Location?.PostalCode,
            Country = entity.Location?.Country,
            Longitude = entity.Location?.Coordinates != null ? entity.Location.Coordinates[0] : null,
            Latitude = entity.Location?.Coordinates != null ? entity.Location.Coordinates[1] : null,
            FuelCategory = entity.Fuel?.Category,
            FuelVolume = entity.Fuel?.Volume,
            FuelUnitPrice = entity.Fuel?.UnitPrice,
            ElectricVolume = entity.Fuel?.ElectricVolume,
            ElectricUnitPrice = entity.Fuel?.ElectricUnitPrice,
            IsFullRefill = entity.Fuel?.IsFullRefill,
            DeltaMileage = entity.Fuel?.DeltaMileage,
            StationId = entity.StationId,
            Garage = entity.Garage,
        };
    }

    public List<CarHistoryModel> ToModels(List<CarHistory> entities)
    {
        var models = new List<CarHistoryModel>(entities.Count);
        foreach (var entity in entities) models.Add(ToModel(entity));
        return models;
    }

    private static CarHistoryLocation BuildLocation(CarHistoryModel model)
    {
        return new CarHistoryLocation
        {
            // City is required on the entity, but an event can legitimately have no location, so the null-forgiving operator keeps that mismatch rather than changing the schema
            City = model.City!,
            PostalCode = model.PostalCode,
            Country = model.Country,
            // a real [lon, lat] pair or nothing, never an empty list, since ToModel indexes [0] and [1] behind a null check an empty list would pass (CarHistoryResourceTest)
            Coordinates = model.Longitude.HasValue && model.Latitude.HasValue
                ? [model.Longitude.Value, model.Latitude.Value]
                : null,
        };
    }

    private static CarHistoryFuel BuildFuel(CarHistoryModel model)
    {
        return new CarHistoryFuel
        {
            Category = model.FuelCategory,
            Volume = model.FuelVolume,
            UnitPrice = model.FuelUnitPrice,
            ElectricVolume = model.ElectricVolume,
            ElectricUnitPrice = model.ElectricUnitPrice,
            IsFullRefill = model.IsFullRefill,
            DeltaMileage = model.DeltaMileage,
        };
    }
}
