using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.WebApi.MappingProfiles;

public class CarDataStorageMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeeptrackCarDataStorageMappingProfile"; }
    }

    public CarDataStorageMappingProfile()
    {
        CreateMap<Car, CarModel>();
        CreateMap<CarModel, Car>();

        MapCarHistoryModel();
        MapCarHistory();
    }

    private void MapCarHistoryModel()
    {
        CreateMap<CarHistory, CarHistoryModel>()
            .ForMember(x => x.City, opt => opt.MapFrom(
                x => x.Location != null ? x.Location.City : null))
            .ForMember(x => x.PostalCode, opt => opt.MapFrom(
                x => x.Location != null ? x.Location.PostalCode : null))
            .ForMember(x => x.Country, opt => opt.MapFrom(
                x => x.Location != null ? x.Location.Country : null))
            .ForMember(x => x.Longitude, opt => opt.MapFrom(
                x => x.Location != null && x.Location.Coordinates != null ? x.Location.Coordinates[0] : (double?)null))
            .ForMember(x => x.Latitude, opt => opt.MapFrom(
                x => x.Location != null && x.Location.Coordinates != null ? x.Location.Coordinates[1] : (double?)null))
            .ForMember(x => x.FuelCategory, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.Category : null))
            .ForMember(x => x.FuelVolume, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.Volume : null))
            .ForMember(x => x.FuelUnitPrice, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.UnitPrice : null))
            .ForMember(x => x.ElectricVolume, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.ElectricVolume : null))
            .ForMember(x => x.ElectricUnitPrice, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.ElectricUnitPrice : null))
            .ForMember(x => x.IsFullRefill, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.IsFullRefill : null))
            .ForMember(x => x.DeltaMileage, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.DeltaMileage : null))
            .ForMember(x => x.StationBrandName, opt => opt.MapFrom(
                x => x.Station != null ? x.Station.BrandName : null));
    }

    private void MapCarHistory()
    {
        CreateMap<CarHistoryModel, CarHistory>()
            // HistoryDate is a plain DateTime on both sides (unlike every other Date field in this codebase,
            // which is DateOnly on the model and goes through DataStorageMappingProfile's DateOnly<->DateTime
            // converter - that converter is what normally stamps DateTimeKind.Utc), so nothing upstream
            // guarantees a Utc Kind here. The Mongo driver's default DateTimeSerializer requires it.
            .ForMember(x => x.HistoryDate, opt => opt.MapFrom(
                x => DateTime.SpecifyKind(x.HistoryDate, DateTimeKind.Utc)))
            .ForMember(x => x.Location, opt => opt.MapFrom(
                x => x))
            .ForMember(x => x.Fuel, opt => opt.MapFrom(
                x => x))
            .ForMember(x => x.Station, opt => opt.MapFrom(
                x => x));

        // Coordinates lives inside CarHistoryLocation (alongside City) - both are location data, so both
        // belong in the one sub-document instead of Coordinates sitting as a separate sibling field on
        // CarHistory itself, which was the original (unreviewed) shape.
        CreateMap<CarHistoryModel, CarHistoryLocation>()
            .ForMember(x => x.Coordinates, opt =>
            {
                // AllowNull() is required here: AllowNullDestinationValues = false (Program.cs) otherwise
                // substitutes a new empty List<double> for a null MapFrom result (same class of gotcha as
                // ReferenceMatchModel.Creator, documented in CLAUDE.md) - MapCarHistoryModel's reverse mapping
                // reads Coordinates[0]/[1] guarded by "!= null", which an empty (not null) list defeats,
                // throwing IndexOutOfRange the moment Longitude/Latitude are unset. Caught by a real-MongoDB
                // CarHistoryResourceTest create/read round-trip, not by a mocked unit test.
                opt.MapFrom(x => (x.Longitude.HasValue && x.Latitude.HasValue) ? new List<double> { x.Longitude.Value, x.Latitude.Value } : null);
                opt.AllowNull();
            });

        CreateMap<CarHistoryModel, CarHistoryFuel>()
            .ForMember(x => x.Category, opt => opt.MapFrom(
                x => x.FuelCategory))
            .ForMember(x => x.Volume, opt => opt.MapFrom(
                x => x.FuelVolume))
            .ForMember(x => x.UnitPrice, opt => opt.MapFrom(
                x => x.FuelUnitPrice));

        CreateMap<CarHistoryModel, CarHistoryStation>()
            .ForMember(x => x.BrandName, opt => opt.MapFrom(
                x => x.StationBrandName));
    }
}
