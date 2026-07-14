using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
public partial class TvShowStorageMapper : IStorageMapper<TvShowModel, TvShow>
{
    public partial TvShow ToEntity(TvShowModel model);

    public partial TvShowModel ToModel(TvShow entity);

    public partial List<TvShowModel> ToModels(List<TvShow> entities);
}
