using System;
using System.Linq.Expressions;
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

    /// <summary>
    /// The title sort's per-query collation: strength 2 orders case- and diacritic-insensitively
    /// ("Apple" between "ant" and "bee", "é" next to "e") without a normalized shadow field or a
    /// collated index. MongoDB rejects a collation combined with a $text filter, which is fine here:
    /// every repository's GetFilter searches via a regex Contains, never $text (the base default
    /// below is legacy - see the index script's car_text removal note).
    /// </summary>
    private static readonly Collation s_titleCollation = new("en", strength: CollationStrength.Secondary);

    public async Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input, string? sort = null)
    {
        var collection = GetCollection();
        var filter = GetFilter(ownerId, search, input);

        var totalCount = await collection.CountDocumentsAsync(filter);

        var options = sort == ListSort.Title && SortTitleField is not null
            ? new FindOptions { Collation = s_titleCollation }
            : null;

        var entities = await collection
            .Find(filter, options)
            .Sort(GetSort(sort))
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

    /// <summary>
    /// Field behind the <see cref="ListSort.Title"/> sort key; null (the default) means this collection
    /// doesn't offer that sort and the key falls back to newest-first. An expression rather than an
    /// element-name string, so the BSON name mapping stays with the entity class.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortTitleField => null;

    /// <summary>Field behind the <see cref="ListSort.Rating"/> sort key (descending, unrated items last) - same contract as <see cref="SortTitleField"/>.</summary>
    protected virtual Expression<Func<TEntity, object>>? SortRatingField => null;

    /// <summary>
    /// "_id" descending doubles as the "recently added" default (ObjectIds embed their creation
    /// timestamp, so no separate created-at field is needed) and as the deterministic tie-break
    /// appended to every other sort.
    /// </summary>
    private SortDefinition<TEntity> GetSort(string? sort)
    {
        var builder = Builders<TEntity>.Sort;
        return sort switch
        {
            ListSort.Title when SortTitleField is not null => builder.Ascending(SortTitleField).Descending("_id"),
            ListSort.Rating when SortRatingField is not null => builder.Descending(SortRatingField).Descending("_id"),
            _ => builder.Descending("_id"),
        };
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
