using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;

namespace Keeptrack.WebApi.MappingProfiles;

public class HouseDataStorageMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeeptrackHouseDataStorageMappingProfile"; }
    }

    public HouseDataStorageMappingProfile()
    {
        CreateMap<House, HouseModel>();
        CreateMap<HouseModel, House>();

        // HistoryDate is DateOnly on the model, DateTime on the entity - the DateOnly<->DateTime converter
        // registered in DataStorageMappingProfile (which also stamps DateTimeKind.Utc) applies automatically,
        // same as every other date field in the app except Car's (see CarDataStorageMappingProfile for why
        // Car needed its own explicit conversion instead).
        CreateMap<HouseHistory, HouseHistoryModel>();
        CreateMap<HouseHistoryModel, HouseHistory>();
    }
}
