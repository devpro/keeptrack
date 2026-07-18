using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class VideoGameRepository(IMongoDatabase mongoDatabase, ILogger<VideoGameRepository> logger, IStorageMapper<VideoGameModel, VideoGame> mapper)
    : MongoDbRepositoryBase<VideoGameModel, VideoGame>(mongoDatabase, logger, mapper), IVideoGameRepository
{
    protected override string CollectionName => "videogame";

    protected override Expression<Func<VideoGame, object>> SortTitleField => x => x.Title;

    protected override Expression<Func<VideoGame, object>> SortRatingField => x => x.Rating!;

    /// <summary>
    /// "Last completed" needs the max <c>CompletedAt</c> across a game's <see cref="VideoGame.Platforms"/>
    /// array, not a single scalar field, so it can't use the shared <c>SortSecondaryDateField</c> hook.
    /// MongoDB natively compares a dotted array field by its max element on a descending sort - no
    /// aggregation pipeline needed (the existing <c>AnyEq(f => f.Platforms.Select(p => p.State), ...)</c>
    /// filter above already confirms the driver resolves this entity's "platforms.*" dotted paths).
    /// </summary>
    protected override SortDefinition<VideoGame> GetSort(string? sort) =>
        sort == ListSort.LastCompleted
            ? Builders<VideoGame>.Sort.Descending("platforms.completed_at").Descending("_id")
            : base.GetSort(sort);

    protected override FilterDefinition<VideoGame> GetFilter(string ownerId, string? search, VideoGameModel input)
    {
        var builder = Builders<VideoGame>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (!string.IsNullOrEmpty(input.State)) filter &= builder.AnyEq(f => f.Platforms.Select(p => p.State), input.State);
        if (!string.IsNullOrEmpty(input.Platform)) filter &= builder.AnyEq(f => f.Platforms.Select(p => p.Platform), input.Platform);
        // "owned" means at least one platform entry (a game's copies) - the platform-entry equivalent of
        // MovieRepository.GetFilter's owned-versions rule
        if (input.IsOwned) filter &= builder.SizeGt(f => f.Platforms, 0);
        // WishlistController.BuildWishlistAsync still relies on this filter-probe clause even though the
        // list page's own "Wishlist" toggle button was removed - don't drop it again.
        if (input.IsWishlisted) filter &= builder.Eq(f => f.IsWishlisted, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null)
    {
        var builder = Builders<VideoGame>.Filter;
        var filter = builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(title)}$", "i"))
                     & builder.Eq(f => f.Year, year)
                     & UnresolvedFilter();

        var update = Builders<VideoGame>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle);
        if (canonicalYear is not null) update = update.Set(f => f.Year, canonicalYear);
        var result = await GetCollection().UpdateManyAsync(filter, update);
        return result.ModifiedCount;
    }

    public async Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync()
    {
        var groups = await GetCollection().Aggregate()
            .Match(UnresolvedFilter())
            .Group(f => new { f.Title, f.Year }, g => g.Key)
            .ToListAsync();
        // no creator dimension for this type - the tuple stays one shape across all five repositories
        return groups.Select(g => (g.Title, g.Year, (string?)null)).ToList();
    }

    /// <summary>
    /// "Has no reference link yet" means <see cref="VideoGame.ReferenceId"/> is null OR empty string, not
    /// just null: old documents (written before the AutoMapper -> Mapperly migration) can still store ""
    /// for an unset field; new writes store a real null instead (Mapperly preserves nulls, and the Mongo
    /// driver's IgnoreIfNullConvention then omits it entirely). Both generations must match.
    /// </summary>
    private static FilterDefinition<VideoGame> UnresolvedFilter()
    {
        var builder = Builders<VideoGame>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
