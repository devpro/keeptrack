using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class AlbumDtoMapper : IDtoMapper<AlbumDto, AlbumModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(AlbumModel.OwnerId), "")]
    public partial AlbumModel ToModel(AlbumDto dto);

    [MapperIgnoreSource(nameof(AlbumModel.OwnerId))]
    public partial AlbumDto ToDto(AlbumModel model);
}
