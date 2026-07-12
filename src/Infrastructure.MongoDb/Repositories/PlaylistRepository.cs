using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class PlaylistRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<PlaylistModel, Playlist>> logger, IStorageMapper<PlaylistModel, Playlist> mapper)
    : MongoDbRepositoryBase<PlaylistModel, Playlist>(mongoDatabase, logger, mapper), IPlaylistRepository
{
    protected override string CollectionName => "playlist";

    protected override FilterDefinition<Playlist> GetFilter(string ownerId, string? search, PlaylistModel input)
    {
        var builder = Builders<Playlist>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}
