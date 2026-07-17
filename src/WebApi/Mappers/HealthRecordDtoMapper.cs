using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
public partial class HealthRecordDtoMapper : IDtoMapper<HealthRecordDto, HealthRecordModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(HealthRecordModel.OwnerId), "")]
    public partial HealthRecordModel ToModel(HealthRecordDto dto);

    [MapperIgnoreSource(nameof(HealthRecordModel.OwnerId))]
    public partial HealthRecordDto ToDto(HealthRecordModel model);
}
