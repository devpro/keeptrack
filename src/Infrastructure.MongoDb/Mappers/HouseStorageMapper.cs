using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class HouseStorageMapper : IStorageMapper<HouseModel, House>
{
    public partial House ToEntity(HouseModel model);

    public partial HouseModel ToModel(House entity);

    public partial List<HouseModel> ToModels(List<House> entities);
}
