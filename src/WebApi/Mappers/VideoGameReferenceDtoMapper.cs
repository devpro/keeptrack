using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only (see <see cref="TvShowReferenceDtoMapper"/>).
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
