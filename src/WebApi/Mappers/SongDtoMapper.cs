using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class SongDtoMapper : IDtoMapper<SongDto, SongModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(SongModel.OwnerId), "")]
    public partial SongModel ToModel(SongDto dto);

    [MapperIgnoreSource(nameof(SongModel.OwnerId))]
    public partial SongDto ToDto(SongModel model);
}
