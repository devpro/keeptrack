using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only: admins submit a <c>LinkReferenceRequestDto</c>, never a whole <see cref="TvShowReferenceDto"/>.
/// <see cref="TvShowReferenceDto.Cast"/> is hydrated by <see cref="ReferenceData.ReferenceDataController"/>, since the model carries only a <c>PersonReferenceId</c> and the name and photo come from <c>person_reference</c>.
/// </summary>
[Mapper]
public partial class TvShowReferenceDtoMapper
{
    [MapperIgnoreTarget(nameof(TvShowReferenceDto.Cast))]
    [MapperIgnoreSource(nameof(TvShowReferenceModel.TitleNormalized))]
    [MapperIgnoreSource(nameof(TvShowReferenceModel.ExternalIds))]
    [MapperIgnoreSource(nameof(TvShowReferenceModel.MatchedAliases))]
    [MapperIgnoreSource(nameof(TvShowReferenceModel.Cast))]
    [MapperIgnoreSource(nameof(TvShowReferenceModel.LastEnrichedAt))]
    // sync bookkeeping (when a rating source was last asked), like LastEnrichedAt, of no use to a client
    [MapperIgnoreSource(nameof(TvShowReferenceModel.RatingsCheckedAt))]
    public partial TvShowReferenceDto ToDto(TvShowReferenceModel model);
}
