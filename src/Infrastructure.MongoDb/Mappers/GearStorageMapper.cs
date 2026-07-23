using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class GearStorageMapper : IStorageMapper<GearModel, Gear>
{
    // IsOwned is filter-only (derived from OwnedVersions) - see MovieStorageMapper.
    [MapperIgnoreSource(nameof(GearModel.IsOwned))]
    public partial Gear ToEntity(GearModel model);

    [MapperIgnoreTarget(nameof(GearModel.IsOwned))]
    public partial GearModel ToModel(Gear entity);

    public partial List<GearModel> ToModels(List<Gear> entities);
}
