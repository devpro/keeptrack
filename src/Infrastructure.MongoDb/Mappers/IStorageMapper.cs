using System.Collections.Generic;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// Maps between a Domain model and its MongoDB entity.
/// Implemented per pair by a Mapperly <c>[Mapper]</c> partial class (<c>BookStorageMapper</c>)
/// and injected into <see cref="Repositories.MongoDbRepositoryBase{TModel, TEntity}"/>, which keeps the base class generic.
/// </summary>
public interface IStorageMapper<TModel, TEntity>
{
    TEntity ToEntity(TModel model);

    TModel ToModel(TEntity entity);

    List<TModel> ToModels(List<TEntity> entities);
}
