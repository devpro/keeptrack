using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Injected directly into <see cref="Repositories.ExploreCatalogueRepository"/>, since an owner-less collection never goes through <see cref="Repositories.MongoDbRepositoryBase{TModel, TEntity}"/> (see <see cref="TvShowReferenceStorageMapper"/>).
/// </summary>
[Mapper]
public partial class ExploreCatalogueEntryStorageMapper
{
    public partial ExploreCatalogueEntry ToEntity(ExploreCatalogueEntryModel model);

    public partial ExploreCatalogueEntryModel ToModel(ExploreCatalogueEntry entity);

    public partial List<ExploreCatalogueEntryModel> ToModels(List<ExploreCatalogueEntry> entities);
}
