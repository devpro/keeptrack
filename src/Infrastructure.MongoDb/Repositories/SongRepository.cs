using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class SongRepository(IMongoDatabase mongoDatabase, ILogger<SongRepository> logger, IStorageMapper<SongModel, Song> mapper)
    : MongoDbRepositoryBase<SongModel, Song>(mongoDatabase, logger, mapper), ISongRepository
{
    protected override string CollectionName => "song";

    protected override FilterDefinition<Song> GetFilter(string ownerId, string? search, SongModel input)
    {
        var builder = Builders<Song>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search))
        {
            filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                          || (f.Artist != null && f.Artist.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)));
        }

        if (!string.IsNullOrEmpty(input.AlbumId)) filter &= builder.Eq(f => f.AlbumId, input.AlbumId);
        if (!string.IsNullOrEmpty(input.TrackPosition)) filter &= builder.Eq(f => f.TrackPosition, input.TrackPosition);

        return filter;
    }
}
