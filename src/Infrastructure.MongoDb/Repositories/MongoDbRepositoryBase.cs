using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// MongoDB Data Access Layer repository abstract class.
/// </summary>
/// <typeparam name="TModel">Data Model class</typeparam>
/// <typeparam name="TEntity">Business class</typeparam>
public abstract class MongoDbRepositoryBase<TModel, TEntity>(
    IMongoDatabase mongoDatabase,
    ILogger<MongoDbRepositoryBase<TModel, TEntity>> logger,
    IStorageMapper<TModel, TEntity> mapper)
    where TEntity : IHasIdAndOwnerId
{
    protected abstract string CollectionName { get; }

    protected ILogger<MongoDbRepositoryBase<TModel, TEntity>> Logger { get; } = logger;

    private IStorageMapper<TModel, TEntity> Mapper { get; } = mapper;

    /// <summary>
    /// "Not found" must stay a real <c>null</c>, not a mapped default instance: Mapperly throws on a null
    /// source rather than substituting a default instance, so the missing-document check has to happen
    /// before mapping regardless - this guard is what makes that "not found" case behave as null instead
    /// of propagating an exception.
    /// </summary>
    public async Task<TModel?> FindOneAsync(string id, string ownerId)
    {
        var entity = await GetCollection().Find(x => x.Id == id && x.OwnerId == ownerId).FirstOrDefaultAsync();
        return entity is null ? default : Mapper.ToModel(entity);
    }

    public async Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input)
    {
        var collection = GetCollection();
        var filter = GetFilter(ownerId, search, input);

        var totalCount = await collection.CountDocumentsAsync(filter);

        var entities = await collection
            .Find(filter)
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync();

        return new PagedResult<TModel>(
            Mapper.ToModels(entities),
            totalCount,
            page,
            pageSize
        );
    }

    public async Task<long> CountAsync(string ownerId) =>
        await GetCollection().CountDocumentsAsync(Builders<TEntity>.Filter.Eq(f => f.OwnerId, ownerId));

    public async Task<TModel> CreateAsync(TModel model)
    {
        var entity = Mapper.ToEntity(model);
        await GetCollection().InsertOneAsync(entity);
        return Mapper.ToModel(entity);
    }

    public async Task<long> UpdateAsync(string id, TModel model, string ownerId)
    {
        var entity = Mapper.ToEntity(model);
        var result = await GetCollection().ReplaceOneAsync(x => x.Id == id && x.OwnerId == ownerId, entity);
        return result.ModifiedCount;
    }

    public async Task<long> DeleteAsync(string id, string ownerId)
    {
        var result = await GetCollection().DeleteOneAsync(x => x.Id == id && x.OwnerId == ownerId);
        return result.DeletedCount;
    }

    protected virtual FilterDefinition<TEntity> GetFilter(string ownerId, string? search, TModel input)
    {
        var builder = Builders<TEntity>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Text(search);
        return filter;
    }

    protected IMongoCollection<TEntity> GetCollection()
    {
        return mongoDatabase.GetCollection<TEntity>(CollectionName);
    }
}
