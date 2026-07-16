using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class AlbumDtoMapper : IDtoMapper<AlbumDto, AlbumModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(AlbumModel.OwnerId), "")]
    // ImageUrl is server-hydrated presentation data (see IReferenceLinkedDto) - no model counterpart in either direction.
    [MapperIgnoreSource(nameof(AlbumDto.ImageUrl))]
    public partial AlbumModel ToModel(AlbumDto dto);

    [MapperIgnoreSource(nameof(AlbumModel.OwnerId))]
    [MapperIgnoreTarget(nameof(AlbumDto.ImageUrl))]
    public partial AlbumDto ToDto(AlbumModel model);
}
