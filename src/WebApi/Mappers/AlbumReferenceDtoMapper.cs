using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Model to DTO only (see <see cref="TvShowReferenceDtoMapper"/>).
/// <see cref="AlbumReferenceDto.ArtistName"/> and <see cref="AlbumReferenceDto.ArtistImageUrl"/> are hydrated by <see cref="ReferenceData.ReferenceDataController"/>, as in <see cref="BookReferenceDtoMapper"/>.
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
