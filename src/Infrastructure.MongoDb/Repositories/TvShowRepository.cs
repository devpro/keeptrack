using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class TvShowRepository(IMongoDatabase mongoDatabase, ILogger<TvShowRepository> logger, IStorageMapper<TvShowModel, TvShow> mapper)
    : MongoDbRepositoryBase<TvShowModel, TvShow>(mongoDatabase, logger, mapper), ITvShowRepository
{
    protected override string CollectionName => "tvshow";

    protected override Expression<Func<TvShow, object>> SortTitleField => x => x.Title;

    protected override Expression<Func<TvShow, object>> SortRatingField => x => x.Rating!;

    protected override Expression<Func<TvShow, object>> SortReferenceRatingField => x => x.ReferenceRating!;

    protected override FilterDefinition<TvShow> GetFilter(string ownerId, string? search, TvShowModel input)
    {
        var builder = Builders<TvShow>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        if (input.State is not null) filter &= builder.Eq(f => f.State, input.State);
        // "owned" means at least one owned version - see MovieRepository.GetFilter
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
        // WishlistController.BuildWishlistAsync still relies on this filter-probe clause even though the
        // list page's own "Wishlist" toggle button was removed - don't drop it again.
        if (input.IsWishlisted) filter &= builder.Eq(f => f.IsWishlisted, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, double? canonicalRating = null, double? canonicalRatingScale = null, string? canonicalRatingSource = null)
    {
        var builder = Builders<TvShow>.Filter;
        var filter = builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(title)}$", "i"))
                     & builder.Eq(f => f.Year, year)
                     & UnresolvedFilter();

        var update = Builders<TvShow>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle)
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

    public Task<long> CountLinkedOnOtherRatingSourceAsync(string source) =>
        ReferenceRatingQueries.CountLinkedOnOtherSourceAsync(GetCollection(), source);

    public async Task<IReadOnlyList<TvShowModel>> FindFinishedLinkedShowsAsync()
    {
        var builder = Builders<TvShow>.Filter;
        // "linked" is the inverse of UnresolvedFilter: a real reference id, not null and not the legacy empty-string sentinel.
        var filter = builder.Eq(f => f.State, TvShowStatus.Finished)
                     & builder.Ne(f => f.ReferenceId, null)
                     & builder.Ne(f => f.ReferenceId, string.Empty);
        var entities = await GetCollection().Find(filter).ToListAsync();
        return Mapper.ToModels(entities);
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

    public Task<IReadOnlyList<string>> FindLinkedReferenceIdsAsync(string ownerId) =>
        ExploreExclusionQueries.FindLinkedReferenceIdsAsync(GetCollection(), ownerId, f => f.ReferenceId);

    public Task<IReadOnlyList<string>> FindDistinctTitlesAsync(string ownerId) =>
        ExploreExclusionQueries.FindDistinctTitlesAsync(GetCollection(), ownerId, f => f.Title);

    /// <summary>
    /// "Has no reference link yet" means <see cref="TvShow.ReferenceId"/> is null OR empty string, not
    /// just null: old documents (written before the AutoMapper -> Mapperly migration) can still store ""
    /// for an unset field; new writes store a real null instead (Mapperly preserves nulls, and the Mongo
    /// driver's IgnoreIfNullConvention then omits it entirely). Both generations must match.
    /// </summary>
    private static FilterDefinition<TvShow> UnresolvedFilter()
    {
        var builder = Builders<TvShow>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
