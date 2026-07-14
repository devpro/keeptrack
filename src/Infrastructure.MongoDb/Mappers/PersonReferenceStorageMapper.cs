using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly by <see cref="Repositories.PersonReferenceRepository"/> - see
/// <see cref="TvShowReferenceStorageMapper"/> for why this has no shared interface.
/// </summary>
[Mapper]
public partial class PersonReferenceStorageMapper
{
    public partial PersonReference ToEntity(PersonReferenceModel model);

    public partial PersonReferenceModel ToModel(PersonReference entity);
}
