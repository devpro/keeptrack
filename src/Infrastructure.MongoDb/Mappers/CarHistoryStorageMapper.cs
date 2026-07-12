using System;
using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Hand-written rather than a Mapperly <c>[Mapper]</c> class: <see cref="CarHistoryModel"/>'s flat
/// City/PostalCode/Country/Longitude/Latitude/Fuel*/StationBrandName fields fan out into
/// <see cref="CarHistory"/>'s Location/Fuel/Station sub-documents on write and back on read, which is
/// bespoke enough that explicit C# is more readable than attribute configuration.
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
            // HistoryDate is a plain DateTime on both sides (the only date field in the codebase that
            // isn't DateOnly on the model), so nothing upstream stamps DateTimeKind.Utc - the Mongo
            // driver's default DateTimeSerializer requires it.
            HistoryDate = DateTime.SpecifyKind(model.HistoryDate, DateTimeKind.Utc),
            Mileage = model.Mileage,
            EventType = model.EventType,
            Description = model.Description,
            Cost = model.Cost,
            Location = BuildLocation(model),
            Fuel = BuildFuel(model),
            Station = BuildStation(model),
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
            StationBrandName = entity.Station?.BrandName,
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
            // CarHistoryLocation.City is `required` at the entity/schema level, but a non-Refuel event
            // can legitimately carry no location at all - the null-forgiving operator here preserves that
            // existing schema/model mismatch rather than introducing a new one.
            City = model.City!,
            PostalCode = model.PostalCode,
            Country = model.Country,
            // Coordinates: never persist an empty list, only a real 2-element [lon, lat] pair or nothing -
            // the read side (ToModel) indexes Coordinates[0]/[1] guarded by "!= null", which an empty
            // (not null) list would defeat. Covered by CarHistoryResourceTest's create/read round-trip.
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

    private static CarHistoryStation BuildStation(CarHistoryModel model)
    {
        return new CarHistoryStation
        {
            // BrandName is `required` on the entity for the same reason City is above - preserved as-is.
            BrandName = model.StationBrandName!,
        };
    }
}
