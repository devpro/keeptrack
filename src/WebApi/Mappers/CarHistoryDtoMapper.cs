using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class CarHistoryDtoMapper : IDtoMapper<CarHistoryDto, CarHistoryModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper).
    // StationBrandName and StationCity are hydrated from the station (CarStationHydrator) and never read from client input, or an entry could claim a name contradicting its StationId.
    [MapValue(nameof(CarHistoryModel.OwnerId), "")]
    [MapperIgnoreSource(nameof(CarHistoryDto.StationBrandName))]
    [MapperIgnoreSource(nameof(CarHistoryDto.StationCity))]
    public partial CarHistoryModel ToModel(CarHistoryDto dto);

    [MapperIgnoreSource(nameof(CarHistoryModel.OwnerId))]
    [MapperIgnoreTarget(nameof(CarHistoryDto.StationBrandName))]
    [MapperIgnoreTarget(nameof(CarHistoryDto.StationCity))]
    public partial CarHistoryDto ToDto(CarHistoryModel model);
}
