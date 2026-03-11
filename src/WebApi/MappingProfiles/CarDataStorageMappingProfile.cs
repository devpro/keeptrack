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
            .ForMember(x => x.Longitude, opt => opt.MapFrom(
                x => x.Coordinates != null ? x.Coordinates[0] : (double?)null))
            .ForMember(x => x.Latitude, opt => opt.MapFrom(
                x => x.Coordinates != null ? x.Coordinates[1] : (double?)null))
            .ForMember(x => x.Amount, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.Amount : null))
            .ForMember(x => x.IsFullTank, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.IsFullTank : null))
            .ForMember(x => x.DeltaMileage, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.DeltaMileage : null))
            .ForMember(x => x.LastRefuelHistoryId, opt => opt.MapFrom(
                x => x.Fuel != null ? x.Fuel.LastRefuelHistoryId : null));
    }

    private void MapCarHistory()
    {
        CreateMap<CarHistoryModel, CarHistory>()
            .ForMember(x => x.Location, opt => opt.MapFrom(
                x => x))
            .ForMember(x => x.Coordinates, opt => opt.MapFrom(
                x => (x.Longitude.HasValue && x.Latitude.HasValue) ? new List<double> { x.Longitude.Value, x.Latitude.Value } : null))
            .ForMember(x => x.Fuel, opt => opt.MapFrom(
                x => x))
            .ForMember(x => x.Station, opt => opt.MapFrom(
                x => x));

        CreateMap<CarHistoryModel, CarHistoryLocation>();

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
