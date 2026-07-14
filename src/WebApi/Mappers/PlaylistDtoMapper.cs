using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class PlaylistDtoMapper : IDtoMapper<PlaylistDto, PlaylistModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(PlaylistModel.OwnerId), "")]
    public partial PlaylistModel ToModel(PlaylistDto dto);

    [MapperIgnoreSource(nameof(PlaylistModel.OwnerId))]
    public partial PlaylistDto ToDto(PlaylistModel model);
}
