using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class MovieRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<MovieModel, Movie>> logger, IMapper mapper)
    : MongoDbRepositoryBase<MovieModel, Movie>(mongoDatabase, logger, mapper), IMovieRepository
{
    protected override string CollectionName => "movie";

    protected override FilterDefinition<Movie> GetFilter(string ownerId, string? search, MovieModel input)
    {
        var builder = Builders<Movie>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        if (input.WantToWatch) filter &= builder.Eq(f => f.WantToWatch, true);
        return filter;
    }
}
