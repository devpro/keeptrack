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

    protected override Expression<Func<VideoGame, object>> SortReferenceRatingField => x => x.ReferenceRating!;

    /// <summary>
    /// "Last completed" sorts by the latest <c>CompletedAt</c> across <see cref="VideoGame.Platforms"/>, not a single field, so it cannot use the <c>SortSecondaryDateField</c> hook.
    /// A descending sort on a dotted array field compares by its maximum element, so no aggregation pipeline is needed.
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
        // owned means at least one platform entry, a game's copies, as MovieRepository.GetFilter does with owned versions
        if (input.IsOwned) filter &= builder.SizeGt(f => f.Platforms, 0);
        // WishlistController.BuildWishlistAsync relies on this clause, although no list page offers the filter
        if (input.IsWishlisted) filter &= builder.Eq(f => f.IsWishlisted, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(ReferenceLinkTarget target, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null)
    {
        var builder = Builders<VideoGame>.Filter;
        var filter = ReferenceLinkFilter(target, () => builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(target.Title!)}$", "i"))
                                                   & builder.Eq(f => f.Year, target.Year)
                                                   & UnresolvedFilter());

        var update = Builders<VideoGame>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle)
            .Set(f => f.ReferenceRating, canonicalRating).Set(f => f.ReferenceRatingScale, canonicalRatingScale)
            .Set(f => f.ReferenceRatingSource, canonicalRatingSource);
        if (canonicalYear is not null) update = update.Set(f => f.Year, canonicalYear);
        var result = await GetCollection().UpdateManyAsync(filter, update);
        return result.ModifiedCount;
    }

    public Task<long> SetReferenceRatingAsync(string referenceId, double? rating, double? ratingScale, string? source) =>
        ReferenceRatingQueries.SetRatingAsync(GetCollection(), referenceId, rating, ratingScale, source);

    public Task<long> SetReferenceRatingsAsync(IReadOnlyList<(string ReferenceId, double? Rating, double? RatingScale, string? Source)> updates) =>
        ReferenceRatingQueries.SetRatingsAsync(GetCollection(), updates);

    public async Task<long> RepointReferenceAsync(string fromReferenceId, string toReferenceId)
    {
        var filter = Builders<VideoGame>.Filter.Eq(f => f.ReferenceId, fromReferenceId);
        var result = await GetCollection().UpdateManyAsync(filter, Builders<VideoGame>.Update.Set(f => f.ReferenceId, toReferenceId));
        return result.ModifiedCount;
    }

    public Task<long> CountLinkedOnOtherRatingSourceAsync(string source) =>
        ReferenceRatingQueries.CountLinkedOnOtherSourceAsync(GetCollection(), source);

    public Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync(string ownerId) =>
        ExploreExclusionQueries.FindLinkedReferenceIdsAsync(GetCollection(), ownerId, f => f.ReferenceId);

    public Task<IReadOnlyList<string>> FindDistinctTitlesAsync(string ownerId) =>
        ExploreExclusionQueries.FindDistinctTitlesAsync(GetCollection(), ownerId, f => f.Title);

    public async Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync()
    {
        var groups = await GetCollection().Aggregate()
            .Match(UnresolvedFilter())
            .Group(f => new { f.Title, f.Year }, g => g.Key)
            .ToListAsync();
        // no creator for this type, the tuple keeping one shape across the five repositories
        return groups.Select(g => (g.Title, g.Year, (string?)null)).ToList();
    }

    /// <summary>
    /// "Not linked yet" means <see cref="VideoGame.ReferenceId"/> is null, missing or empty.
    /// Older documents store "" for an unset field, while newer ones omit it, and both must match.
    /// </summary>
    private static FilterDefinition<VideoGame> UnresolvedFilter()
    {
        var builder = Builders<VideoGame>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
