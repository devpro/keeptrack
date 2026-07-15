using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class VideoGameDtoMapper : IDtoMapper<VideoGameDto, VideoGameModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(VideoGameModel.OwnerId), "")]
    // ImageUrl is server-hydrated presentation data (see IReferenceLinkedDto) - no model counterpart in either direction.
    [MapperIgnoreSource(nameof(VideoGameDto.ImageUrl))]
    public partial VideoGameModel ToModel(VideoGameDto dto);

    [MapperIgnoreSource(nameof(VideoGameModel.OwnerId))]
    [MapperIgnoreTarget(nameof(VideoGameDto.ImageUrl))]
    public partial VideoGameDto ToDto(VideoGameModel model);
}
