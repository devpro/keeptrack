using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly by <see cref="Repositories.TvShowReferenceRepository"/> - the owner-less reference
/// repositories are purpose-built already and need no shared <see cref="IStorageMapper{TModel, TEntity}"/>
/// abstraction, per <c>docs/automapper-removal-plan.md</c>.
/// </summary>
[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class TvShowReferenceStorageMapper
{
    public partial TvShowReference ToEntity(TvShowReferenceModel model);

    public partial TvShowReferenceModel ToModel(TvShowReference entity);
}
