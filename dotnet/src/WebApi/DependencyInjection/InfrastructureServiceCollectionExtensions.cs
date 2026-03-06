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

        services.TryAddScoped<Domain.Repositories.IBookRepository, Dal.MongoDb.Repositories.BookRepository>();
        services.TryAddScoped<Domain.Repositories.ICarRepository, Dal.MongoDb.Repositories.CarRepository>();
        services.TryAddScoped<Domain.Repositories.ICarHistoryRepository, Dal.MongoDb.Repositories.CarHistoryRepository>();
        services.TryAddScoped<Domain.Repositories.IMovieRepository, Dal.MongoDb.Repositories.MovieRepository>();
        services.TryAddScoped<Domain.Repositories.ITvShowRepository, Dal.MongoDb.Repositories.TvShowRepository>();
        services.TryAddScoped<Domain.Repositories.IVideoGameRepository, Dal.MongoDb.Repositories.VideoGameRepository>();
    }
}
