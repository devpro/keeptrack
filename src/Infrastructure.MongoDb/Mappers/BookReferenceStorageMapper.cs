using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly by <see cref="Repositories.BookReferenceRepository"/> - see
/// <see cref="TvShowReferenceStorageMapper"/> for why this has no shared interface.
/// </summary>
[Mapper]
public partial class BookReferenceStorageMapper
{
    public partial BookReference ToEntity(BookReferenceModel model);

    public partial BookReferenceModel ToModel(BookReference entity);
}
