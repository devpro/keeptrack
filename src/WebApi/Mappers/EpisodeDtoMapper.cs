using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
public partial class EpisodeDtoMapper : IDtoMapper<EpisodeDto, EpisodeModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(EpisodeModel.OwnerId), "")]
    public partial EpisodeModel ToModel(EpisodeDto dto);

    [MapperIgnoreSource(nameof(EpisodeModel.OwnerId))]
    public partial EpisodeDto ToDto(EpisodeModel model);
}
