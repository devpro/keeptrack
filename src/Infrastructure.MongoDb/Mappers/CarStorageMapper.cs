using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class CarStorageMapper : IStorageMapper<CarModel, Car>
{
    public partial Car ToEntity(CarModel model);

    public partial CarModel ToModel(Car entity);

    public partial List<CarModel> ToModels(List<Car> entities);
}
