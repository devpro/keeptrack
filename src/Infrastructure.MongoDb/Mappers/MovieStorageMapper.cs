using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class MovieStorageMapper : IStorageMapper<MovieModel, Movie>
{
    public partial Movie ToEntity(MovieModel model);

    public partial MovieModel ToModel(Movie entity);

    public partial List<MovieModel> ToModels(List<Movie> entities);
}
