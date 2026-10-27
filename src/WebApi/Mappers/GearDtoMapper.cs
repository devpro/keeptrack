using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class GearDtoMapper : IDtoMapper<GearDto, GearModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(GearModel.OwnerId), "")]
    public partial GearModel ToModel(GearDto dto);

    [MapperIgnoreSource(nameof(GearModel.OwnerId))]
    public partial GearDto ToDto(GearModel model);
}
