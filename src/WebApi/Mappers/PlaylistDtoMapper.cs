using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class PlaylistDtoMapper : IDtoMapper<PlaylistDto, PlaylistModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(PlaylistModel.OwnerId), "")]
    public partial PlaylistModel ToModel(PlaylistDto dto);

    [MapperIgnoreSource(nameof(PlaylistModel.OwnerId))]
    public partial PlaylistDto ToDto(PlaylistModel model);
}
