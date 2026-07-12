using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto): admins submit a <c>LinkReferenceRequestDto</c>, never a full
/// <see cref="TvShowReferenceDto"/>, so there's no Dto -> Model direction to map. <see cref="TvShowReferenceDto.Cast"/>
/// is ignored here and hydrated manually by <see cref="ReferenceData.ReferenceDataController"/> - the
/// model only carries a <c>PersonReferenceId</c>, while the Dto needs the person's name/photo joined in
/// from <c>person_reference</c>, a join Mapperly has no repository access to perform.
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
    public partial TvShowReferenceDto ToDto(TvShowReferenceModel model);
}
