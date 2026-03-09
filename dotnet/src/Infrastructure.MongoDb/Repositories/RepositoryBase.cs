using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using KeepTrack.Common.Collections.Generic;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// MongoDB Data Access Layer repository abstract class.
/// </summary>
/// <typeparam name="TModel">Data Model class</typeparam>
/// <typeparam name="TEntity">Business class</typeparam>
public abstract class RepositoryBase<TModel, TEntity>(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<TModel, TEntity>> logger, IMapper mapper)
    where TEntity : IEntity
{
    protected abstract string CollectionName { get; }

    protected ILogger<RepositoryBase<TModel, TEntity>> Logger { get; } = logger;

    protected IMapper Mapper { get; } = mapper;

    protected IMongoCollection<TEntity> GetCollection()
    {
        return mongoDatabase.GetCollection<TEntity>(CollectionName);
    }

    public async Task<TModel?> FindOneAsync(string id, string ownerId)
    {
        var entities = await GetCollection().FindAsync(x => x.Id == id && x.OwnerId == ownerId);
        return Mapper.Map<TModel>(entities.FirstOrDefault());
    }

    // TODO: use PagedRequest instead
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
        return string.IsNullOrEmpty(search)
            ? builder.Eq(f => f.OwnerId, ownerId)
            : builder.Eq(f => f.OwnerId, ownerId) & builder.Text(search);
    }
}
