using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly into <see cref="Repositories.MovieReferenceRepository"/> (see <see cref="TvShowReferenceStorageMapper"/> for why there is no shared interface).
/// </summary>
[Mapper]
public partial class MovieReferenceStorageMapper
{
    public partial MovieReference ToEntity(MovieReferenceModel model);

    public partial MovieReferenceModel ToModel(MovieReference entity);
}
