using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only (see <see cref="TvShowReferenceDtoMapper"/>, which also explains the <see cref="MovieReferenceDto.Cast"/> ignore).
/// </summary>
[Mapper]
public partial class MovieReferenceDtoMapper
{
    [MapperIgnoreTarget(nameof(MovieReferenceDto.Cast))]
    [MapperIgnoreSource(nameof(MovieReferenceModel.TitleNormalized))]
    [MapperIgnoreSource(nameof(MovieReferenceModel.ExternalIds))]
    [MapperIgnoreSource(nameof(MovieReferenceModel.MatchedAliases))]
    [MapperIgnoreSource(nameof(MovieReferenceModel.Cast))]
    [MapperIgnoreSource(nameof(MovieReferenceModel.LastEnrichedAt))]
    // sync bookkeeping (when a rating source was last asked), like LastEnrichedAt, of no use to a client
    [MapperIgnoreSource(nameof(MovieReferenceModel.RatingsCheckedAt))]
    public partial MovieReferenceDto ToDto(MovieReferenceModel model);
}
