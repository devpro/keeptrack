using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class TvShowRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<TvShowModel, TvShow>> logger, IMapper mapper)
    : MongoDbRepositoryBase<TvShowModel, TvShow>(mongoDatabase, logger, mapper), ITvShowRepository
{
    protected override string CollectionName => "tvshow";

    protected override FilterDefinition<TvShow> GetFilter(string ownerId, string? search, TvShowModel input)
    {
        var builder = Builders<TvShow>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        return filter;
    }
}
