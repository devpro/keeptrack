using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly into <see cref="Repositories.VideoGameReferenceRepository"/> (see <see cref="TvShowReferenceStorageMapper"/> for why there is no shared interface).
/// </summary>
[Mapper]
public partial class VideoGameReferenceStorageMapper
{
    public partial VideoGameReference ToEntity(VideoGameReferenceModel model);

    public partial VideoGameReferenceModel ToModel(VideoGameReference entity);
}
