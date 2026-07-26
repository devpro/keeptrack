using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class GearRepository(IMongoDatabase mongoDatabase, ILogger<GearRepository> logger, IStorageMapper<GearModel, Gear> mapper)
    : MongoDbRepositoryBase<GearModel, Gear>(mongoDatabase, logger, mapper), IGearRepository
{
    protected override string CollectionName => "gear";

    protected override Expression<Func<Gear, object>> SortTitleField => x => x.Title;

    /// <summary>
    /// "Bought" needs the max <c>AcquiredAt</c> across a gear item's <see cref="Gear.OwnedVersions"/>
    /// array (the most recently acquired copy), not a single scalar field, so it can't use the shared
    /// <c>SortSecondaryDateField</c> hook - same shape as <c>VideoGameRepository.GetSort</c>'s "last
    /// completed" override, relying on MongoDB's native max-on-descending-sort semantics for a dotted
    /// array field rather than an aggregation pipeline.
    /// </summary>
    protected override SortDefinition<Gear> GetSort(string? sort) =>
        sort == ListSort.Bought
            ? Builders<Gear>.Sort.Descending("owned_versions.acquired_at").Descending("_id")
            : base.GetSort(sort);

    protected override FilterDefinition<Gear> GetFilter(string ownerId, string? search, GearModel input)
    {
        var builder = Builders<Gear>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, StringComparison.CurrentCultureIgnoreCase)
                                                                         || (f.Brand != null && f.Brand.Contains(search, StringComparison.CurrentCultureIgnoreCase)));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        if (!string.IsNullOrEmpty(input.Category)) filter &= builder.Eq(f => f.Category, input.Category);
        // "owned" means at least one owned version - see MovieRepository.GetFilter
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
        return filter;
    }

    public async Task<IReadOnlyList<string>> FindDistinctCategoriesAsync(string ownerId)
    {
        var builder = Builders<Gear>.Filter;
        // "has a category" is the negation of TvShowRepository/MovieRepository's UnresolvedFilter shape
        // (matches null OR empty string) - both generations of "unset" must be excluded here too.
        var filter = builder.Eq(f => f.OwnerId, ownerId) & builder.Ne(f => f.Category, null) & builder.Ne(f => f.Category, string.Empty);
        var cursor = await GetCollection().DistinctAsync(f => f.Category, filter);
        var categories = await cursor.ToListAsync();
        categories.Sort(StringComparer.OrdinalIgnoreCase);
        return categories!;
    }
}
