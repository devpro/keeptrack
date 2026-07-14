using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// One-directional (Model -> Dto) - see <see cref="TvShowReferenceDtoMapper"/> for the general rationale.
/// <see cref="AlbumReferenceDto.ArtistName"/>/<see cref="AlbumReferenceDto.ArtistImageUrl"/> are ignored
/// here and hydrated manually by <see cref="ReferenceData.ReferenceDataController"/> - same reasoning as
/// <see cref="BookReferenceDtoMapper"/>.
/// </summary>
[Mapper]
public partial class AlbumReferenceDtoMapper
{
    [MapperIgnoreTarget(nameof(AlbumReferenceDto.ArtistName))]
    [MapperIgnoreTarget(nameof(AlbumReferenceDto.ArtistImageUrl))]
    [MapperIgnoreSource(nameof(AlbumReferenceModel.TitleNormalized))]
    [MapperIgnoreSource(nameof(AlbumReferenceModel.ArtistReferenceId))]
    [MapperIgnoreSource(nameof(AlbumReferenceModel.ExternalIds))]
    [MapperIgnoreSource(nameof(AlbumReferenceModel.MatchedAliases))]
    [MapperIgnoreSource(nameof(AlbumReferenceModel.LastEnrichedAt))]
    public partial AlbumReferenceDto ToDto(AlbumReferenceModel model);
}
