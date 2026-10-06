using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HouseHistoryDtoMapper : IDtoMapper<HouseHistoryDto, HouseHistoryModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(HouseHistoryModel.OwnerId), "")]
    public partial HouseHistoryModel ToModel(HouseHistoryDto dto);

    [MapperIgnoreSource(nameof(HouseHistoryModel.OwnerId))]
    public partial HouseHistoryDto ToDto(HouseHistoryModel model);
}
