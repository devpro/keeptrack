using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
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

    /// <summary>
    /// The entity &lt;-&gt; model mapper. Protected rather than private so a subclass with its own hand-written
    /// query maps through this single stored instance: capturing the primary-constructor parameter as well
    /// would store the same mapper twice on the type (CS9107).
    /// </summary>
    protected IStorageMapper<TModel, TEntity> Mapper { get; } = mapper;

    /// <summary>
    /// Whether <paramref name="id"/> could name a document in this collection at all.
    /// Every entity reaching this base maps its <c>_id</c> as an ObjectId - the four collections with genuine
    /// string ids (lease, background_job, app_setting, provider_quota) are owner-less and use purpose-built
    /// repositories, so they never come through here. The driver therefore serializes the string in an id
    /// filter through <c>ObjectId.Parse</c> and throws <see cref="FormatException"/> on anything that isn't
    /// 24 hex digits (confirmed against a real MongoDB), which the API surfaced as a 500 and the Blazor app
    /// as its generic error page.
    /// A hand-edited, truncated or stale id in a URL is ordinary client input, not a server fault: it names
    /// no document, exactly like a well-formed id that was never minted, and every caller below already has
    /// a truthful answer for that case (a 404, and the detail page's own "not found" state).
    /// </summary>
    private static bool CanNameADocument(string id) => ObjectId.TryParse(id, out _);

    public async Task<TModel?> FindOneAsync(string id, string ownerId)
    {
        if (!CanNameADocument(id))
        {
            return default;
        }

        var entity = await GetCollection().Find(x => x.Id == id && x.OwnerId == ownerId).FirstOrDefaultAsync();
        return entity is null ? default : Mapper.ToModel(entity);
    }

    public async Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input, string? sort = null)
    {
        var collection = GetCollection();
        var filter = GetFilter(ownerId, search, input);

        var totalCount = await collection.CountDocumentsAsync(filter);

        var options = sort == ListSort.Title && SortTitleField is not null
            ? new FindOptions { Collation = new Collation("en", strength: CollationStrength.Secondary) }
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
    /// Field behind the <see cref="ListSort.Title"/> sort key;
    /// null (the default) means this collection doesn't offer that sort and the key falls back to newest-first.
    /// An expression rather than an element-name string, so the BSON name mapping stays with the entity class.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortTitleField => null;

    /// <summary>
    /// Field behind the <see cref="ListSort.Rating"/> sort key (descending, unrated items last) - same contract as <see cref="SortTitleField"/>.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortRatingField => null;

    /// <summary>
    /// Field behind the <see cref="ListSort.ReferenceRating"/> sort key (descending, items with no linked
    /// reference rating last) - the denormalized copy on the tenant entity, so this stays a plain indexed
    /// sort with no join. Same contract as <see cref="SortTitleField"/>.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortReferenceRatingField => null;

    /// <summary>
    /// Field behind <see cref="ListSort.LastSeen"/>/<see cref="ListSort.LastRead"/> (descending, unset
    /// items last) - same contract as <see cref="SortTitleField"/>. A single hook covers both keys: a
    /// collection only ever advertises one of the two via its own list page's UI (Movie: last seen, Book:
    /// last read), so both keys resolving to the same field is harmless.
    /// </summary>
    protected virtual Expression<Func<TEntity, object>>? SortSecondaryDateField => null;

    /// <summary>
    /// "_id" descending doubles as the "recently added" default (ObjectIds embed their creation timestamp, so no separate created-at field is needed)
    /// and as the deterministic tie-break appended to every other sort. Virtual so a collection whose extra
    /// sort key doesn't fit the single-scalar-field hooks above (e.g. VideoGame's "last completed", the max
    /// of an array field) can add its own case - see VideoGameRepository.GetSort.
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

    public async Task<long> CountAsync(string ownerId)
    {
        return await GetCollection().CountDocumentsAsync(Builders<TEntity>.Filter.Eq(f => f.OwnerId, ownerId));
    }

    public async Task<TModel> CreateAsync(TModel model)
    {
        var entity = Mapper.ToEntity(model);
        await GetCollection().InsertOneAsync(entity);
        return Mapper.ToModel(entity);
    }

    public async Task<long> UpdateAsync(string id, TModel model, string ownerId)
    {
        if (!CanNameADocument(id))
        {
            return 0;
        }

        var entity = Mapper.ToEntity(model);
        var result = await GetCollection().ReplaceOneAsync(x => x.Id == id && x.OwnerId == ownerId, entity);
        return result.ModifiedCount;
    }

    public async Task<long> DeleteAsync(string id, string ownerId)
    {
        if (!CanNameADocument(id))
        {
            return 0;
        }

        var result = await GetCollection().DeleteOneAsync(x => x.Id == id && x.OwnerId == ownerId);
        return result.DeletedCount;
    }

    /// <summary>
    /// Deletes every owner-scoped document whose parent-id field matches - the single implementation behind
    /// each child repository's cascade method (CarHistory/HouseHistory/HealthRecord/Episode). Child entities
    /// are separate top-level collections referencing their parent by id (see CLAUDE.md's "Child entities"
    /// section), so deleting the parent alone would leave them in MongoDB forever, only ever reachable via a
    /// parent id that no longer exists.
    /// The parent field is an expression rather than an element-name string, so the BSON name mapping stays
    /// with the entity class - same contract as <see cref="SortTitleField"/>.
    /// </summary>
    protected async Task<long> DeleteAllByParentAsync(Expression<Func<TEntity, string>> parentIdField, string parentId, string ownerId)
    {
        // A parent id is an ObjectId here too, and the controller's OnDeletedAsync cascade hook runs on the
        // raw route id whether or not the parent delete matched anything - so an unparseable id reaches this
        // far and would throw where the delete above already answered "nothing to remove".
        if (!CanNameADocument(parentId))
        {
            return 0;
        }

        var builder = Builders<TEntity>.Filter;
        var result = await GetCollection().DeleteManyAsync(builder.Eq(f => f.OwnerId, ownerId) & builder.Eq(parentIdField, parentId));
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
    /// Every distinct non-empty value this owner has used in one string field, sorted case-insensitively -
    /// the single implementation behind each "suggest what you've already typed" endpoint
    /// (<c>GearController.GetCategories</c>, <c>CarHistoryController.GetFuelCategories</c>).
    /// The field is an expression rather than an element-name string, so the BSON name mapping stays with
    /// the entity class - same contract as <see cref="SortTitleField"/> and
    /// <see cref="DeleteAllByParentAsync"/>, and the only form that works for a nested field.
    /// </summary>
    protected async Task<IReadOnlyList<string>> FindDistinctValuesAsync(Expression<Func<TEntity, string?>> field, string ownerId)
    {
        var builder = Builders<TEntity>.Filter;
        // "has a value" is the negation of TvShowRepository/MovieRepository's UnresolvedFilter shape
        // (matches null OR empty string) - both generations of "unset" must be excluded here too.
        var filter = builder.Eq(f => f.OwnerId, ownerId) & builder.Ne(field, null) & builder.Ne(field, string.Empty);
        var cursor = await GetCollection().DistinctAsync(field, filter);
        var values = await cursor.ToListAsync();
        values.Sort(StringComparer.OrdinalIgnoreCase);
        return values!;
    }

    protected IMongoCollection<TEntity> GetCollection()
    {
        return mongoDatabase.GetCollection<TEntity>(CollectionName);
    }
}
