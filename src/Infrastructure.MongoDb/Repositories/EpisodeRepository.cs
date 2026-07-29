using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class EpisodeRepository(IMongoDatabase mongoDatabase, ILogger<EpisodeRepository> logger, IStorageMapper<EpisodeModel, Episode> mapper)
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

    public async Task<List<EpisodeModel>> FindByShowIdsAsync(string ownerId, IReadOnlyCollection<string> tvShowIds)
    {
        if (tvShowIds.Count == 0) return [];
        var builder = Builders<Episode>.Filter;
        // owner_id + tv_show_id In(...) matches the leading fields of the episode_last_watched index (owner_id, tv_show_id, watched_at).
        var filter = builder.Eq(f => f.OwnerId, ownerId) & builder.In(f => f.TvShowId, tvShowIds);
        var entities = await GetCollection().Find(filter).ToListAsync();
        return mapper.ToModels(entities);
    }
}
