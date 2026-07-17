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

public class AlbumRepository(IMongoDatabase mongoDatabase, ILogger<AlbumRepository> logger, IStorageMapper<AlbumModel, Album> mapper)
    : MongoDbRepositoryBase<AlbumModel, Album>(mongoDatabase, logger, mapper), IAlbumRepository
{
    protected override string CollectionName => "album";

    protected override Expression<Func<Album, object>> SortTitleField => x => x.Title;

    protected override Expression<Func<Album, object>> SortRatingField => x => x.Rating!;

    protected override FilterDefinition<Album> GetFilter(string ownerId, string? search, AlbumModel input)
    {
        var builder = Builders<Album>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                                                         || f.Artist.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        // "owned" means at least one owned version - see MovieRepository.GetFilter
        if (input.IsOwned) filter &= builder.SizeGt(f => f.OwnedVersions, 0);
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

    public async Task<IReadOnlyList<(string Title, int? Year, string? Creator)>> FindDistinctUnresolvedTitleYearsAsync()
    {
        // any one tenant's artist works as the queue entry's creator - it only prefills the admin's
        // search field, it is never persisted anywhere (see ReferenceDataAdminPage's SearchAsync).
        var groups = await GetCollection().Aggregate()
            .Match(UnresolvedFilter())
            .Group(f => new { f.Title, f.Year }, g => new { g.Key, Creator = g.First().Artist })
            .ToListAsync();
        return groups.Select(g => (g.Key.Title, g.Key.Year, (string?)g.Creator)).ToList();
    }

    /// <summary>
    /// "Has no reference link yet" means <see cref="Album.ReferenceId"/> is null OR empty string, not
    /// just null: old documents (written before the AutoMapper -> Mapperly migration) can still store ""
    /// for an unset field; new writes store a real null instead (Mapperly preserves nulls, and the Mongo
    /// driver's IgnoreIfNullConvention then omits it entirely). Both generations must match.
    /// </summary>
    private static FilterDefinition<Album> UnresolvedFilter()
    {
        var builder = Builders<Album>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
