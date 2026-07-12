using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HouseHistoryDtoMapper : IDtoMapper<HouseHistoryDto, HouseHistoryModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(HouseHistoryModel.OwnerId), "")]
    public partial HouseHistoryModel ToModel(HouseHistoryDto dto);

    [MapperIgnoreSource(nameof(HouseHistoryModel.OwnerId))]
    public partial HouseHistoryDto ToDto(HouseHistoryModel model);
}
