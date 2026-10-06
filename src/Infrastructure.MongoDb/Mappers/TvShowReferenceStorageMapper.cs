using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly into <see cref="Repositories.TvShowReferenceRepository"/>: the reference repositories are purpose-built and need no shared <see cref="IStorageMapper{TModel, TEntity}"/>.
/// </summary>
[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class TvShowReferenceStorageMapper
{
    public partial TvShowReference ToEntity(TvShowReferenceModel model);

    public partial TvShowReferenceModel ToModel(TvShowReference entity);
}
