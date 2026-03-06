using AutoMapper;
using KeepTrack.Dal.MongoDb.Entities;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Dal.MongoDb.Repositories
{
    public class MovieRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<MovieModel, Movie>> logger, IMapper mapper)
        : RepositoryBase<MovieModel, Movie>(mongoDatabase, logger, mapper), IMovieRepository
    {
        protected override string CollectionName => "movie";

        protected override FilterDefinition<Movie> GetFilter(string ownerId, string search, MovieModel input)
        {
            if (string.IsNullOrEmpty(search))
            {
                return base.GetFilter(ownerId, search, input);
            }

            var builder = Builders<Movie>.Filter;
            return builder.Eq(f => f.OwnerId, ownerId)
                   & builder.Where(f => f.Title.ToLower().Contains(search.ToLower()));
        }
    }
}
