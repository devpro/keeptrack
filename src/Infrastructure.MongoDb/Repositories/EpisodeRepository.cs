using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class EpisodeRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<EpisodeModel, Episode>> logger, IMapper mapper)
    : MongoDbRepositoryBase<EpisodeModel, Episode>(mongoDatabase, logger, mapper), IEpisodeRepository
{
    protected override string CollectionName => "episode";

    protected override FilterDefinition<Episode> GetFilter(string ownerId, string? search, EpisodeModel input)
    {
        var builder = Builders<Episode>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(input.TvShowId)) filter &= builder.Eq(f => f.TvShowId, input.TvShowId);
        return filter;
    }
}
