using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories
{
    public class MovieRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<MovieModel, Movie>> logger, IMapper mapper)
        : MongoDbRepositoryBase<MovieModel, Movie>(mongoDatabase, logger, mapper), IMovieRepository
    {
        protected override string CollectionName => "movie";

        protected override FilterDefinition<Movie> GetFilter(string ownerId, string? search, MovieModel input)
        {
            var builder = Builders<Movie>.Filter;
            var filter = builder.Eq(f => f.OwnerId, ownerId);
            if (!string.IsNullOrEmpty(search)) builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
            return filter;
        }
    }
}
