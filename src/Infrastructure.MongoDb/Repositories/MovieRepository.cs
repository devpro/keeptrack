using System.Collections.Generic;
using System.Linq;
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

public class MovieRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<MovieModel, Movie>> logger, IStorageMapper<MovieModel, Movie> mapper)
    : MongoDbRepositoryBase<MovieModel, Movie>(mongoDatabase, logger, mapper), IMovieRepository
{
    protected override string CollectionName => "movie";

    protected override FilterDefinition<Movie> GetFilter(string ownerId, string? search, MovieModel input)
    {
        var builder = Builders<Movie>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        if (input.WantToWatch) filter &= builder.Eq(f => f.WantToWatch, true);
        if (input.IsOwned) filter &= builder.Eq(f => f.IsOwned, true);
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

    public async Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync()
    {
        var groups = await GetCollection().Aggregate()
            .Match(UnresolvedFilter())
            .Group(f => new { f.Title, f.Year }, g => g.Key)
            .ToListAsync();
        return groups.Select(g => (g.Title, g.Year)).ToList();
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
