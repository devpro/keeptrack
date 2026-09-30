using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly by <see cref="Repositories.ExploreCatalogueRepository"/> - see
/// <see cref="TvShowReferenceStorageMapper"/> for why an owner-less collection's mapper has no shared
/// interface (it never goes through <see cref="Repositories.MongoDbRepositoryBase{TModel, TEntity}"/>).
/// </summary>
[Mapper]
public partial class ExploreCatalogueEntryStorageMapper
{
    public partial ExploreCatalogueEntry ToEntity(ExploreCatalogueEntryModel model);

    public partial ExploreCatalogueEntryModel ToModel(ExploreCatalogueEntry entity);

    public partial List<ExploreCatalogueEntryModel> ToModels(List<ExploreCatalogueEntry> entities);
}
