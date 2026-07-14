using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class MovieDtoMapper : IDtoMapper<MovieDto, MovieModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(MovieModel.OwnerId), "")]
    public partial MovieModel ToModel(MovieDto dto);

    [MapperIgnoreSource(nameof(MovieModel.OwnerId))]
    public partial MovieDto ToDto(MovieModel model);
}
