using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class MovieDtoMapper : IDtoMapper<MovieDto, MovieModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(MovieModel.OwnerId), "")]
    // ImageUrl is server-hydrated presentation data (see IReferenceLinkedDto) - no model counterpart in either direction.
    [MapperIgnoreSource(nameof(MovieDto.ImageUrl))]
    public partial MovieModel ToModel(MovieDto dto);

    [MapperIgnoreSource(nameof(MovieModel.OwnerId))]
    [MapperIgnoreTarget(nameof(MovieDto.ImageUrl))]
    public partial MovieDto ToDto(MovieModel model);
}
