using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only (see <see cref="TvShowReferenceDtoMapper"/>).
/// <see cref="BookReferenceDto.AuthorName"/> and <see cref="BookReferenceDto.AuthorImageUrl"/> are hydrated by <see cref="ReferenceData.ReferenceDataController"/>,
/// since the model carries only an <c>AuthorReferenceId</c> and the name comes from <c>person_reference</c>.
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
