using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

public class VideoGameRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<VideoGameModel, VideoGame>> logger, IMapper mapper)
    : RepositoryBase<VideoGameModel, VideoGame>(mongoDatabase, logger, mapper), IVideoGameRepository
{
    protected override string CollectionName => "videogame";

    protected override FilterDefinition<VideoGame> GetFilter(string ownerId, string? search, VideoGameModel input)
    {
        if (string.IsNullOrEmpty(search) && string.IsNullOrEmpty(input.State) && string.IsNullOrEmpty(input.Platform))
        {
            return base.GetFilter(ownerId, search, input);
        }

        var builder = Builders<VideoGame>.Filter;

        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search))
        {
            filter &= builder.Where(f => f.Title.ToLower().Contains(search.ToLower()));
        }

        if (!string.IsNullOrEmpty(input.State))
        {
            filter &= builder.Where(f => f.State == input.State);
        }

        if (!string.IsNullOrEmpty(input.Platform))
        {
            filter &= builder.Where(f => f.Platform == input.Platform);
        }

        return filter;
    }
}
