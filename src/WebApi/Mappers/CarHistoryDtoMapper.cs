using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class CarHistoryDtoMapper : IDtoMapper<CarHistoryDto, CarHistoryModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here.
    // StationBrandName/StationCity are display-only: hydrated server-side from the station the entry's
    // StationId points at (see CarStationHydrator) and never read back off client input, or an entry could
    // claim a station name that contradicts its own StationId.
    [MapValue(nameof(CarHistoryModel.OwnerId), "")]
    [MapperIgnoreSource(nameof(CarHistoryDto.StationBrandName))]
    [MapperIgnoreSource(nameof(CarHistoryDto.StationCity))]
    public partial CarHistoryModel ToModel(CarHistoryDto dto);

    [MapperIgnoreSource(nameof(CarHistoryModel.OwnerId))]
    [MapperIgnoreTarget(nameof(CarHistoryDto.StationBrandName))]
    [MapperIgnoreTarget(nameof(CarHistoryDto.StationCity))]
    public partial CarHistoryDto ToDto(CarHistoryModel model);
}
