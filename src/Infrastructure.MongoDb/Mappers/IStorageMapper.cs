using System.Collections.Generic;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Maps between a Domain model and its MongoDB entity counterpart. Implemented per entity pair by a
/// Mapperly <c>[Mapper]</c> partial class (e.g. <c>BookStorageMapper</c>) and injected into
/// <see cref="Repositories.MongoDbRepositoryBase{TModel, TEntity}"/> instead of AutoMapper's untyped
/// <c>IMapper</c>.
/// </summary>
public interface IStorageMapper<TModel, TEntity>
{
    TEntity ToEntity(TModel model);

    TModel ToModel(TEntity entity);

    List<TModel> ToModels(List<TEntity> entities);
}
