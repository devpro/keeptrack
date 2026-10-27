using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class TvShowDtoMapper : IDtoMapper<TvShowDto, TvShowModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(TvShowModel.OwnerId), "")]
    // ImageUrl is hydrated by the server for display (see IReferenceLinkedDto), with no model counterpart
    [MapperIgnoreSource(nameof(TvShowDto.ImageUrl))]
    public partial TvShowModel ToModel(TvShowDto dto);

    [MapperIgnoreSource(nameof(TvShowModel.OwnerId))]
    [MapperIgnoreTarget(nameof(TvShowDto.ImageUrl))]
    public partial TvShowDto ToDto(TvShowModel model);
}
