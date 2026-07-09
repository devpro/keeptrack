using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Common.System;
using Keeptrack.Infrastructure.MongoDb.Entities;
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
    IMapper mapper)
    where TEntity : IHasIdAndOwnerId
{
    protected abstract string CollectionName { get; }

    protected ILogger<MongoDbRepositoryBase<TModel, TEntity>> Logger { get; } = logger;

    private IMapper Mapper { get; } = mapper;

    /// <summary>
    /// "Not found" must stay a real <c>null</c>, not a mapped default instance: <c>AllowNullDestinationValues
    /// = false</c> (Program.cs) makes <c>Mapper.Map&lt;TModel&gt;(entity)</c> return a new, all-default
    /// <typeparamref name="TModel"/> instead of null when <paramref name="entity"/> itself is null - the same
    /// gotcha already guarded against in the reference-data repositories' own Find* methods, just not here
    /// yet. Without this guard, every controller's <c>GetById</c> "not found" check silently returned 200
    /// with a blank object instead of 404 for any entity type - caught via <c>CarResourceTest</c>, not a
    /// mocked unit test, since a mocked repository never exercises the real mapping configuration.
    /// </summary>
    public async Task<TModel?> FindOneAsync(string id, string ownerId)
    {
        var entity = await GetCollection().Find(x => x.Id == id && x.OwnerId == ownerId).FirstOrDefaultAsync();
        return entity is null ? default : Mapper.Map<TModel>(entity);
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
            Mapper.Map<List<TModel>>(entities),
            totalCount,
            page,
            pageSize
        );
    }

    public async Task<TModel> CreateAsync(TModel model)
    {
        var entity = Mapper.Map<TEntity>(model);
        await GetCollection().InsertOneAsync(entity);
        return Mapper.Map<TModel>(entity);
    }

    public async Task<long> UpdateAsync(string id, TModel model, string ownerId)
    {
        var entity = Mapper.Map<TEntity>(model);
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
