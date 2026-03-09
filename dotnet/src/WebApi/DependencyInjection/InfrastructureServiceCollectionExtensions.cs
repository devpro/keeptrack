using KeepTrack.Infrastructure.MongoDb.Repositories;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;

namespace KeepTrack.WebApi.DependencyInjection;

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

        services.TryAddScoped<Domain.Repositories.IBookRepository, BookMongoDbRepository>();
        services.TryAddScoped<Domain.Repositories.ICarRepository, CarMongoDbRepository>();
        services.TryAddScoped<Domain.Repositories.ICarHistoryRepository, CarHistoryMongoDbRepository>();
        services.TryAddScoped<Domain.Repositories.IMovieRepository, MovieMongoDbRepository>();
        services.TryAddScoped<Domain.Repositories.ITvShowRepository, TvShowMongoDbRepository>();
        services.TryAddScoped<Domain.Repositories.IVideoGameRepository, VideoGameMongoDbRepository>();
    }
}
