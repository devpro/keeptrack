using System.Collections.Generic;
using System.Threading.Tasks;
using AutoMapper;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// MongoDB Data Access Layer repository abstract class.
/// </summary>
/// <typeparam name="T">Data Model class</typeparam>
/// <typeparam name="U">Business class</typeparam>
public abstract class RepositoryBase<T, U>(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<T, U>> logger, IMapper mapper)
    where U : IEntity
{
    protected abstract string CollectionName { get; }

    protected ILogger<RepositoryBase<T, U>> Logger { get; } = logger;

    protected IMapper Mapper { get; } = mapper;

    protected IMongoCollection<U> GetCollection()
    {
        return mongoDatabase.GetCollection<U>(CollectionName);
    }

    public async Task<T?> FindOneAsync(string id, string ownerId)
    {
        var collection = GetCollection();
        var dbEntries = await collection.FindAsync(x => x.Id == id && x.OwnerId == ownerId);
        return Mapper.Map<T>(dbEntries.FirstOrDefault());
    }

    public async Task<List<T>> FindAllAsync(string ownerId, int page, int pageSize, string search, T input)
    {
        var collection = GetCollection();
        var dbEntries = await collection
            .Find(GetFilter(ownerId, search, input))
            .Skip(page * pageSize)
            .Limit(pageSize)
            .ToListAsync();
        return Mapper.Map<List<T>>(dbEntries);
    }

    public async Task<T> CreateAsync(T model)
    {
        var collection = GetCollection();
        var entity = Mapper.Map<U>(model);
        await collection.InsertOneAsync(entity);
        return Mapper.Map<T>(entity);
    }

    public async Task<long> UpdateAsync(string id, T model, string ownerId)
    {
        var collection = GetCollection();
        var entity = Mapper.Map<U>(model);
        var result = await collection.ReplaceOneAsync(x => x.Id == id && x.OwnerId == ownerId, entity);
        return result.ModifiedCount;
    }

    public async Task<long> DeleteAsync(string id, string ownerId)
    {
        var collection = GetCollection();
        var result = await collection.DeleteOneAsync(x => x.Id == id && x.OwnerId == ownerId);
        return result.DeletedCount;
    }

    protected virtual FilterDefinition<U> GetFilter(string ownerId, string search, T input)
    {
        var builder = Builders<U>.Filter;
        if (string.IsNullOrEmpty(search))
        {
            return builder.Eq(f => f.OwnerId, ownerId);
        }

        return builder.Eq(f => f.OwnerId, ownerId) & builder.Text(search);
    }
}
