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

public class MovieRepository(IMongoDatabase mongoDatabase, ILogger<MovieRepository> logger, IStorageMapper<MovieModel, Movie> mapper)
    : MongoDbRepositoryBase<MovieModel, Movie>(mongoDatabase, logger, mapper), IMovieRepository
{
    protected override string CollectionName => "movie";

    protected override Expression<Func<Movie, object>> SortTitleField => x => x.Title;

    protected override Expression<Func<Movie, object>> SortRatingField => x => x.Rating!;

    protected override Expression<Func<Movie, object>> SortSecondaryDateField => x => x.FirstSeenAt!;

    protected override FilterDefinition<Movie> GetFilter(string ownerId, string? search, MovieModel input)
    {
        var builder = Builders<Movie>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        if (input.WantToWatch) filter &= builder.Eq(f => f.WantToWatch, true);
        // "owned" means at least one owned version - renders as { "owned_versions.0": { $exists: true } }
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
        if (input.IsUnseen) filter &= builder.Eq(f => f.FirstSeenAt, null);
        // WishlistController.BuildWishlistAsync still relies on this filter-probe clause even though the
        // list page's own "Wishlist" toggle button was removed - don't drop it again.
        if (input.IsWishlisted) filter &= builder.Eq(f => f.IsWishlisted, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null)
    {
        var builder = Builders<Movie>.Filter;
        var filter = builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(title)}$", "i"))
                     & builder.Eq(f => f.Year, year)
                     & UnresolvedFilter();

        var update = Builders<Movie>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle);
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
    /// "Has no reference link yet" means <see cref="Movie.ReferenceId"/> is null OR empty string, not
    /// just null: old documents (written before the AutoMapper -> Mapperly migration) can still store ""
    /// for an unset field; new writes store a real null instead (Mapperly preserves nulls, and the Mongo
    /// driver's IgnoreIfNullConvention then omits it entirely). Both generations must match.
    /// </summary>
    private static FilterDefinition<Movie> UnresolvedFilter()
    {
        var builder = Builders<Movie>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
