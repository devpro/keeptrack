using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class EpisodeStorageMapper : IStorageMapper<EpisodeModel, Episode>
{
    public partial Episode ToEntity(EpisodeModel model);

    public partial EpisodeModel ToModel(Episode entity);

    public partial List<EpisodeModel> ToModels(List<Episode> entities);
}
