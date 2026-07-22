using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class GearDtoMapper : IDtoMapper<GearDto, GearModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(GearModel.OwnerId), "")]
    public partial GearModel ToModel(GearDto dto);

    [MapperIgnoreSource(nameof(GearModel.OwnerId))]
    public partial GearDto ToDto(GearModel model);
}
