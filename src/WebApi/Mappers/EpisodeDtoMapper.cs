using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
public partial class EpisodeDtoMapper : IDtoMapper<EpisodeDto, EpisodeModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(EpisodeModel.OwnerId), "")]
    public partial EpisodeModel ToModel(EpisodeDto dto);

    [MapperIgnoreSource(nameof(EpisodeModel.OwnerId))]
    public partial EpisodeDto ToDto(EpisodeModel model);
}
