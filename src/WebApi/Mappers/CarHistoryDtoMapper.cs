using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class CarHistoryDtoMapper : IDtoMapper<CarHistoryDto, CarHistoryModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(CarHistoryModel.OwnerId), "")]
    public partial CarHistoryModel ToModel(CarHistoryDto dto);

    [MapperIgnoreSource(nameof(CarHistoryModel.OwnerId))]
    public partial CarHistoryDto ToDto(CarHistoryModel model);
}
