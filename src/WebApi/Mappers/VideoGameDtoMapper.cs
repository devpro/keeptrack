using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class VideoGameDtoMapper : IDtoMapper<VideoGameDto, VideoGameModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(VideoGameModel.OwnerId), "")]
    // ImageUrl is hydrated by the server for display (see IReferenceLinkedDto), with no model counterpart
    [MapperIgnoreSource(nameof(VideoGameDto.ImageUrl))]
    public partial VideoGameModel ToModel(VideoGameDto dto);

    [MapperIgnoreSource(nameof(VideoGameModel.OwnerId))]
    [MapperIgnoreTarget(nameof(VideoGameDto.ImageUrl))]
    public partial VideoGameDto ToDto(VideoGameModel model);
}
