using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto) - see <see cref="TvShowReferenceDtoMapper"/> for the general rationale.
/// </summary>
[Mapper]
public partial class VideoGameReferenceDtoMapper
{
    [MapperIgnoreSource(nameof(VideoGameReferenceModel.TitleNormalized))]
    [MapperIgnoreSource(nameof(VideoGameReferenceModel.ExternalIds))]
    [MapperIgnoreSource(nameof(VideoGameReferenceModel.MatchedAliases))]
    [MapperIgnoreSource(nameof(VideoGameReferenceModel.LastEnrichedAt))]
    public partial VideoGameReferenceDto ToDto(VideoGameReferenceModel model);
}
