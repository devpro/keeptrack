using System;
using System.Linq.Expressions;
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

    protected override FilterDefinition<Gear> GetFilter(string ownerId, string? search, GearModel input)
    {
        var builder = Builders<Gear>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, StringComparison.CurrentCultureIgnoreCase)
                                                                         || (f.Brand != null && f.Brand.Contains(search, StringComparison.CurrentCultureIgnoreCase)));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        // "owned" means at least one owned version - see MovieRepository.GetFilter
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
        return filter;
    }
}
