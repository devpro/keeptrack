using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class MovieDtoMapper : IDtoMapper<MovieDto, MovieModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(MovieModel.OwnerId), "")]
    // ImageUrl is hydrated by the server for display (see IReferenceLinkedDto), with no model counterpart
    [MapperIgnoreSource(nameof(MovieDto.ImageUrl))]
    public partial MovieModel ToModel(MovieDto dto);

    [MapperIgnoreSource(nameof(MovieModel.OwnerId))]
    [MapperIgnoreTarget(nameof(MovieDto.ImageUrl))]
    public partial MovieDto ToDto(MovieModel model);
}
