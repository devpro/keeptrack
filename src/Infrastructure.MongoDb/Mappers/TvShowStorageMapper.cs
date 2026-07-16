using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class TvShowStorageMapper : IStorageMapper<TvShowModel, TvShow>
{
    // IsOwned is filter-only (derived from OwnedVersions) - see MovieStorageMapper.
    [MapperIgnoreSource(nameof(TvShowModel.IsOwned))]
    public partial TvShow ToEntity(TvShowModel model);

    [MapperIgnoreTarget(nameof(TvShowModel.IsOwned))]
    public partial TvShowModel ToModel(TvShow entity);

    public partial List<TvShowModel> ToModels(List<TvShow> entities);
}
