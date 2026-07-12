using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class HouseDtoMapper : IDtoMapper<HouseDto, HouseModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(HouseModel.OwnerId), "")]
    public partial HouseModel ToModel(HouseDto dto);

    [MapperIgnoreSource(nameof(HouseModel.OwnerId))]
    public partial HouseDto ToDto(HouseModel model);
}
