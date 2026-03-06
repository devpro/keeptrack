using AutoMapper;
using KeepTrack.Dal.MongoDb.Entities;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Dal.MongoDb.Repositories;

public class TvShowRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<TvShowModel, TvShow>> logger, IMapper mapper)
    : RepositoryBase<TvShowModel, TvShow>(mongoDatabase, logger, mapper), ITvShowRepository
{
    protected override string CollectionName => "tvshow";

    protected override FilterDefinition<TvShow> GetFilter(string ownerId, string search, TvShowModel input)
    {
        if (string.IsNullOrEmpty(search))
        {
            return base.GetFilter(ownerId, search, input);
        }

        var builder = Builders<TvShow>.Filter;
        return builder.Eq(f => f.OwnerId, ownerId) & builder.Where(f => f.Title.ToLower().Contains(search.ToLower()));
    }
}
