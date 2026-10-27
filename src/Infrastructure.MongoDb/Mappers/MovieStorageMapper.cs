using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class MovieStorageMapper : IStorageMapper<MovieModel, Movie>
{
    // IsOwned is filter only, with no entity field: ownership derives from OwnedVersions being non-empty, never stored as a flag
    [MapperIgnoreSource(nameof(MovieModel.IsOwned))]
    [MapperIgnoreSource(nameof(MovieModel.IsUnseen))]
    public partial Movie ToEntity(MovieModel model);

    [MapperIgnoreTarget(nameof(MovieModel.IsOwned))]
    [MapperIgnoreTarget(nameof(MovieModel.IsUnseen))]
    public partial MovieModel ToModel(Movie entity);

    public partial List<MovieModel> ToModels(List<Movie> entities);
}
