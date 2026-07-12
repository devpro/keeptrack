using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto) - see <see cref="TvShowReferenceDtoMapper"/> for the general rationale.
/// <see cref="BookReferenceDto.AuthorName"/>/<see cref="BookReferenceDto.AuthorImageUrl"/> are ignored here
/// and hydrated manually by <see cref="ReferenceData.ReferenceDataController"/>: the model only carries an
/// <c>AuthorReferenceId</c>, the Dto needs the person's name joined in from <c>person_reference</c>.
/// </summary>
[Mapper]
public partial class BookReferenceDtoMapper
{
    [MapperIgnoreTarget(nameof(BookReferenceDto.AuthorName))]
    [MapperIgnoreTarget(nameof(BookReferenceDto.AuthorImageUrl))]
    [MapperIgnoreSource(nameof(BookReferenceModel.TitleNormalized))]
    [MapperIgnoreSource(nameof(BookReferenceModel.AuthorReferenceId))]
    [MapperIgnoreSource(nameof(BookReferenceModel.ExternalIds))]
    [MapperIgnoreSource(nameof(BookReferenceModel.MatchedAliases))]
    [MapperIgnoreSource(nameof(BookReferenceModel.LastEnrichedAt))]
    public partial BookReferenceDto ToDto(BookReferenceModel model);
}
