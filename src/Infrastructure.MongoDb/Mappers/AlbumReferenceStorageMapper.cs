using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly by <see cref="Repositories.AlbumReferenceRepository"/> - see
/// <see cref="TvShowReferenceStorageMapper"/> for why this has no shared interface.
/// </summary>
[Mapper]
public partial class AlbumReferenceStorageMapper
{
    public partial AlbumReference ToEntity(AlbumReferenceModel model);

    public partial AlbumReferenceModel ToModel(AlbumReference entity);
}
