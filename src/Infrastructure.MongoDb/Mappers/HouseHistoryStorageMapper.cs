using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class HouseHistoryStorageMapper : IStorageMapper<HouseHistoryModel, HouseHistory>
{
    public partial HouseHistory ToEntity(HouseHistoryModel model);

    public partial HouseHistoryModel ToModel(HouseHistory entity);

    public partial List<HouseHistoryModel> ToModels(List<HouseHistory> entities);
}
