using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class CollectibleStorageMapper : IStorageMapper<CollectibleModel, Collectible>
{
    // IsOwned is filter-only (derived from OwnedVersions) - see MovieStorageMapper.
    [MapperIgnoreSource(nameof(CollectibleModel.IsOwned))]
    public partial Collectible ToEntity(CollectibleModel model);

    [MapperIgnoreTarget(nameof(CollectibleModel.IsOwned))]
    public partial CollectibleModel ToModel(Collectible entity);

    public partial List<CollectibleModel> ToModels(List<Collectible> entities);
}
