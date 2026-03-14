using Keeptrack.Infrastructure.MongoDb.Repositories;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;

namespace Keeptrack.WebApi.DependencyInjection;

internal static class InfrastructureServiceCollectionExtensions
{
    internal static void AddMongoDbInfrastructure(this IServiceCollection services, AppConfiguration configuration)
    {
        services.AddSingleton<IMongoClient>(sp =>
        {
            var pack = new ConventionPack
            {
                new CamelCaseElementNameConvention(),
                new EnumRepresentationConvention(BsonType.String),
                new IgnoreExtraElementsConvention(true),
                new IgnoreIfNullConvention(true)
            };
            ConventionRegistry.Register("Conventions", pack, t => true);
            return new MongoClient(configuration.ConnectionString);
        });

        services.AddSingleton<IMongoDatabase>(sp =>
            sp.GetRequiredService<IMongoClient>().GetDatabase(configuration.DatabaseName));

        services.TryAddScoped<Domain.Repositories.IBookRepository, BookRepository>();
        services.TryAddScoped<Domain.Repositories.ICarRepository, CarRepository>();
        services.TryAddScoped<Domain.Repositories.ICarHistoryRepository, CarHistoryRepository>();
        services.TryAddScoped<Domain.Repositories.IMovieRepository, MovieRepository>();
        services.TryAddScoped<Domain.Repositories.IMusicAlbumRepository, MusicAlbumRepository>();
        services.TryAddScoped<Domain.Repositories.ITvShowRepository, TvShowRepository>();
        services.TryAddScoped<Domain.Repositories.IVideoGameRepository, VideoGameRepository>();
    }
}
