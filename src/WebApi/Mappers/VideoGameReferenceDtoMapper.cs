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
    // bookkeeping for the admin reconciliation queue, of no interest to a detail page
    [MapperIgnoreSource(nameof(VideoGameReferenceModel.ProviderAdoptionCheckedAt))]
    public partial VideoGameReferenceDto ToDto(VideoGameReferenceModel model);
}
