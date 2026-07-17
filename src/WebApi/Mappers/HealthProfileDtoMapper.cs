using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class HealthProfileDtoMapper : IDtoMapper<HealthProfileDto, HealthProfileModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(HealthProfileModel.OwnerId), "")]
    public partial HealthProfileModel ToModel(HealthProfileDto dto);

    [MapperIgnoreSource(nameof(HealthProfileModel.OwnerId))]
    public partial HealthProfileDto ToDto(HealthProfileModel model);
}
