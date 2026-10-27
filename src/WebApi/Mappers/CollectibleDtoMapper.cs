using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class CollectibleDtoMapper : IDtoMapper<CollectibleDto, CollectibleModel>
{
    // MapValue rather than MapperIgnoreTarget, since OwnerId is required (see BookDtoMapper)
    [MapValue(nameof(CollectibleModel.OwnerId), "")]
    public partial CollectibleModel ToModel(CollectibleDto dto);

    [MapperIgnoreSource(nameof(CollectibleModel.OwnerId))]
    public partial CollectibleDto ToDto(CollectibleModel model);
}
