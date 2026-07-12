using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class VideoGameDtoMapper : IDtoMapper<VideoGameDto, VideoGameModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(VideoGameModel.OwnerId), "")]
    public partial VideoGameModel ToModel(VideoGameDto dto);

    [MapperIgnoreSource(nameof(VideoGameModel.OwnerId))]
    public partial VideoGameDto ToDto(VideoGameModel model);
}
