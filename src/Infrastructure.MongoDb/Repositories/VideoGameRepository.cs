using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class VideoGameRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<VideoGameModel, VideoGame>> logger, IMapper mapper)
    : MongoDbRepositoryBase<VideoGameModel, VideoGame>(mongoDatabase, logger, mapper), IVideoGameRepository
{
    protected override string CollectionName => "videogame";

    protected override FilterDefinition<VideoGame> GetFilter(string ownerId, string? search, VideoGameModel input)
    {
        var builder = Builders<VideoGame>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (!string.IsNullOrEmpty(input.State)) filter &= builder.Where(f => f.State == input.State);
        if (!string.IsNullOrEmpty(input.Platform)) filter &= builder.Where(f => f.Platform == input.Platform);
        return filter;
    }
}
