using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class MusicAlbumRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<MusicAlbumModel, MusicAlbum>> logger, IMapper mapper)
    : MongoDbRepositoryBase<MusicAlbumModel, MusicAlbum>(mongoDatabase, logger, mapper), IMusicAlbumRepository
{
    protected override string CollectionName => "movie";

    protected override FilterDefinition<MusicAlbum> GetFilter(string ownerId, string? search, MusicAlbumModel input)
    {
        var builder = Builders<MusicAlbum>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                                              || f.Artist.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}

