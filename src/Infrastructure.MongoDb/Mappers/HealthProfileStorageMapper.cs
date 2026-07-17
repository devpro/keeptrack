using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class HealthProfileStorageMapper : IStorageMapper<HealthProfileModel, HealthProfile>
{
    public partial HealthProfile ToEntity(HealthProfileModel model);

    public partial HealthProfileModel ToModel(HealthProfile entity);

    public partial List<HealthProfileModel> ToModels(List<HealthProfile> entities);
}
