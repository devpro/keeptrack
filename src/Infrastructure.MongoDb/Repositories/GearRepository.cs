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
    /// "Bought" sorts by the latest <c>AcquiredAt</c> across <see cref="Gear.OwnedVersions"/>, not a single field, so it cannot use the <c>SortSecondaryDateField</c> hook.
    /// A descending sort on a dotted array field compares by its maximum, so no aggregation pipeline is needed, as in <c>VideoGameRepository.GetSort</c>.
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
        // owned means at least one owned version (see MovieRepository.GetFilter)
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
        return filter;
    }

    public Task<IReadOnlyList<string>> FindDistinctCategoriesAsync(string ownerId)
        => FindDistinctValuesAsync(f => f.Category, ownerId);
}
