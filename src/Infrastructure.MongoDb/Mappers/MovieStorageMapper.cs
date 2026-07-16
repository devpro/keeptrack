using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class MovieStorageMapper : IStorageMapper<MovieModel, Movie>
{
    // IsOwned is a filter-only member on MovieModel with no entity field - ownership is derived from
    // OwnedVersions being non-empty, never stored as its own flag. See VideoGameStorageMapper for the
    // filter-only ignore convention.
    [MapperIgnoreSource(nameof(MovieModel.IsOwned))]
    public partial Movie ToEntity(MovieModel model);

    [MapperIgnoreTarget(nameof(MovieModel.IsOwned))]
    public partial MovieModel ToModel(Movie entity);

    public partial List<MovieModel> ToModels(List<Movie> entities);
}
