using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class AlbumRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<AlbumModel, Album>> logger, IMapper mapper)
    : MongoDbRepositoryBase<AlbumModel, Album>(mongoDatabase, logger, mapper), IAlbumRepository
{
    protected override string CollectionName => "album";

    protected override FilterDefinition<Album> GetFilter(string ownerId, string? search, AlbumModel input)
    {
        var builder = Builders<Album>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                                                         || f.Artist.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalArtist = null, string? canonicalGenre = null)
    {
        var builder = Builders<Album>.Filter;
        var filter = builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(title)}$", "i"))
                     & builder.Eq(f => f.Year, year)
                     & UnresolvedFilter();

        var update = Builders<Album>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle);
        if (canonicalYear is not null) update = update.Set(f => f.Year, canonicalYear);
        if (canonicalArtist is not null) update = update.Set(f => f.Artist, canonicalArtist);
        if (canonicalGenre is not null) update = update.Set(f => f.Genre, canonicalGenre);
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
    /// "Has no reference link yet" means <see cref="Album.ReferenceId"/> is null OR empty string, not
    /// just null: AutoMapper is configured with <c>AllowNullDestinationValues = false</c> (see Program.cs),
    /// so mapping a model with a null string property stores an empty string, never an actual null.
    /// </summary>
    private static FilterDefinition<Album> UnresolvedFilter()
    {
        var builder = Builders<Album>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
