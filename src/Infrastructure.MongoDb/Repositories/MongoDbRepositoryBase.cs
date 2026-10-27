using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

/// <summary>
/// The owner-scoped CRUD every user-owned collection shares.
/// </summary>
/// <typeparam name="TModel">Domain model</typeparam>
/// <typeparam name="TEntity">MongoDB entity</typeparam>
public abstract class MongoDbRepositoryBase<TModel, TEntity>(
    IMongoDatabase mongoDatabase,
    ILogger<MongoDbRepositoryBase<TModel, TEntity>> logger,
    IStorageMapper<TModel, TEntity> mapper)
    where TEntity : IHasIdAndOwnerId
{
    protected abstract string CollectionName { get; }

    protected ILogger<MongoDbRepositoryBase<TModel, TEntity>> Logger { get; } = logger;

    /// <summary>
    /// Protected, so a subclass with its own query maps through this one instance, since also capturing the primary-constructor parameter would store the mapper twice (CS9107).
    /// </summary>
    protected IStorageMapper<TModel, TEntity> Mapper { get; } = mapper;

    /// <summary>
    /// Whether <paramref name="id"/> could name a document of this collection at all.
    /// Every entity here stores its <c>_id</c> as an ObjectId, since the collections with string ids use purpose-built repositories.
    /// The driver parses the id of a filter through <c>ObjectId.Parse</c> and throws <see cref="FormatException"/> on anything but 24 hex digits, which would become a 500.
    /// A truncated or edited id in a URL is client input naming no document, like an id never minted, so every caller answers it as not found.
    /// </summary>
    private static bool CanNameADocument(string id) => ObjectId.TryParse(id, out _);

    /// <summary>
    /// The records a reference link is written to, see <see cref="ReferenceLinkTarget"/>.
    /// <paramref name="adminMatch"/> carries the domain's own unlinked filter, since an admin's link never replaces a link already made.
    /// </summary>
    protected static FilterDefinition<TEntity> ReferenceLinkFilter(ReferenceLinkTarget target, Func<FilterDefinition<TEntity>> adminMatch) =>
        target.ItemId is not null
            ? Builders<TEntity>.Filter.Where(x => x.Id == target.ItemId && x.OwnerId == target.OwnerId)
            : adminMatch();

    public async Task<TModel?> FindOneAsync(string id, string ownerId, CancellationToken cancellationToken = default)
    {
        if (!CanNameADocument(id))
        {
            return default;
        }

        var entity = await GetCollection().Find(x => x.Id == id && x.OwnerId == ownerId).FirstOrDefaultAsync(cancellationToken);
        return entity is null ? default : Mapper.ToModel(entity);
    }

    public async Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input, string? sort = null, CancellationToken cancellationToken = default)
    {
        var collection = GetCollection();
        var filter = GetFilter(ownerId, search, input);

        var totalCount = await collection.CountDocumentsAsync(filter, cancellationToken: cancellationToken);

        var options = sort == ListSort.Title && SortTitleField is not null
            ? new FindOptions { Collation = new Collation("en", strength: CollationStrength.Secondary) }
            : null;

        var entities = await collection
            .Find(filter, options)
            .Sort(GetSort(sort))
            .Skip((page - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<TModel>(
            Mapper.ToModels(entities),
            totalCount,
            page,
            pageSize
        );
    }

    /// <summary>
    /// The field behind the <see cref="ListSort.Title"/> sort key, or null when the collection does not offer it and the key falls back to newest first.
    /// An expression rather than an element name, so the BSON name mapping stays with the entity class.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortTitleField => null;

    /// <summary>
    /// The field behind the <see cref="ListSort.Rating"/> sort key (descending, unrated last), like <see cref="SortTitleField"/>.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortRatingField => null;

    /// <summary>
    /// The field behind the <see cref="ListSort.ReferenceRating"/> sort key (descending, unrated last), like <see cref="SortTitleField"/>.
    /// It is the copy on the tenant entity, so the sort stays a plain indexed one with no join.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortReferenceRatingField => null;

    /// <summary>
    /// The field behind <see cref="ListSort.LastSeen"/> and <see cref="ListSort.LastRead"/> (descending, unset last), like <see cref="SortTitleField"/>.
    /// One hook covers both keys, since a list page offers only one of them (last seen for movies, last read for books).
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortSecondaryDateField => null;

    /// <summary>
    /// "_id" descending is the "recently added" default, since an ObjectId embeds its creation time, and the deterministic tie-break of every other sort.
    /// Virtual, so a sort key that is not a single field (video games' "last completed", the maximum of an array field) adds its own case (see <c>VideoGameRepository.GetSort</c>).
    /// </summary>
    protected virtual SortDefinition<TEntity> GetSort(string? sort)
    {
        var builder = Builders<TEntity>.Sort;
        return sort switch
        {
            ListSort.Title when SortTitleField is not null => builder.Ascending(SortTitleField).Descending("_id"),
            ListSort.Rating when SortRatingField is not null => builder.Descending(SortRatingField).Descending("_id"),
            ListSort.ReferenceRating when SortReferenceRatingField is not null => builder.Descending(SortReferenceRatingField).Descending("_id"),
            ListSort.LastSeen or ListSort.LastRead when SortSecondaryDateField is not null => builder.Descending(SortSecondaryDateField).Descending("_id"),
            _ => builder.Descending("_id")
        };
    }

    public async Task<long> CountAsync(string ownerId, CancellationToken cancellationToken = default)
    {
        return await GetCollection().CountDocumentsAsync(Builders<TEntity>.Filter.Eq(f => f.OwnerId, ownerId), cancellationToken: cancellationToken);
    }

    public async Task<TModel> CreateAsync(TModel model, CancellationToken cancellationToken = default)
    {
        var entity = Mapper.ToEntity(model);
        await GetCollection().InsertOneAsync(entity, cancellationToken: cancellationToken);
        return Mapper.ToModel(entity);
    }

    public async Task<long> UpdateAsync(string id, TModel model, string ownerId, CancellationToken cancellationToken = default)
    {
        if (!CanNameADocument(id))
        {
            return 0;
        }

        var entity = Mapper.ToEntity(model);
        var result = await GetCollection().ReplaceOneAsync(x => x.Id == id && x.OwnerId == ownerId, entity, cancellationToken: cancellationToken);
        return result.ModifiedCount;
    }

    public async Task<long> DeleteAsync(string id, string ownerId, CancellationToken cancellationToken = default)
    {
        if (!CanNameADocument(id))
        {
            return 0;
        }

        var result = await GetCollection().DeleteOneAsync(x => x.Id == id && x.OwnerId == ownerId, cancellationToken);
        return result.DeletedCount;
    }

    /// <summary>
    /// Deletes every owner-scoped document whose parent id matches, behind each child repository's cascade.
    /// A child references its parent by id (see docs/data-model.md's "Child entities" section), so deleting the parent alone would orphan it forever.
    /// The parent field is an expression, like <see cref="SortTitleField"/>.
    /// </summary>
    protected async Task<long> DeleteAllByParentAsync(Expression<Func<TEntity, string>> parentIdField, string parentId, string ownerId, CancellationToken cancellationToken = default)
    {
        // the cascade runs on the raw route id whether or not the parent delete matched, so an unparseable id reaches here and must answer "nothing to remove" rather than throw
        if (!CanNameADocument(parentId))
        {
            return 0;
        }

        var builder = Builders<TEntity>.Filter;
        var result = await GetCollection().DeleteManyAsync(builder.Eq(f => f.OwnerId, ownerId) & builder.Eq(parentIdField, parentId), cancellationToken);
        return result.DeletedCount;
    }

    protected virtual FilterDefinition<TEntity> GetFilter(string ownerId, string? search, TModel input)
    {
        var builder = Builders<TEntity>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Text(search);
        return filter;
    }

    /// <summary>
    /// Every distinct non-empty value this owner used in one string field, sorted case-insensitively,
    /// behind each suggestion endpoint (<c>GearController.GetCategories</c>, <c>CarHistoryController.GetFuelCategories</c>).
    /// The field is an expression like <see cref="SortTitleField"/>, the only form that works for a nested field.
    /// </summary>
    protected async Task<IReadOnlyList<string>> FindDistinctValuesAsync(Expression<Func<TEntity, string?>> field, string ownerId, CancellationToken cancellationToken = default)
    {
        var builder = Builders<TEntity>.Filter;
        // excludes null, missing and empty, the inverse of UnresolvedFilter
        var filter = builder.Eq(f => f.OwnerId, ownerId) & builder.Ne(field, null) & builder.Ne(field, string.Empty);
        var cursor = await GetCollection().DistinctAsync(field, filter, cancellationToken: cancellationToken);
        var values = await cursor.ToListAsync(cancellationToken);
        values.Sort(StringComparer.OrdinalIgnoreCase);
        return values!;
    }

    protected IMongoCollection<TEntity> GetCollection()
    {
        return mongoDatabase.GetCollection<TEntity>(CollectionName);
    }
}
