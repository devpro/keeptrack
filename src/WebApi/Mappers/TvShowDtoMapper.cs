using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class TvShowDtoMapper : IDtoMapper<TvShowDto, TvShowModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(TvShowModel.OwnerId), "")]
    // ImageUrl is server-hydrated presentation data (see IReferenceLinkedDto) - no model counterpart in either direction.
    [MapperIgnoreSource(nameof(TvShowDto.ImageUrl))]
    public partial TvShowModel ToModel(TvShowDto dto);

    [MapperIgnoreSource(nameof(TvShowModel.OwnerId))]
    [MapperIgnoreTarget(nameof(TvShowDto.ImageUrl))]
    public partial TvShowDto ToDto(TvShowModel model);
}
