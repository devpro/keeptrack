using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class AlbumDtoMapper : IDtoMapper<AlbumDto, AlbumModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(AlbumModel.OwnerId), "")]
    // ImageUrl is hydrated by the server for display (see IReferenceLinkedDto), with no model counterpart
    [MapperIgnoreSource(nameof(AlbumDto.ImageUrl))]
    public partial AlbumModel ToModel(AlbumDto dto);

    [MapperIgnoreSource(nameof(AlbumModel.OwnerId))]
    [MapperIgnoreTarget(nameof(AlbumDto.ImageUrl))]
    public partial AlbumDto ToDto(AlbumModel model);
}
