namespace Keeptrack.WebApi.MappingProfiles;

public class DataStorageMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeeptrackDataStorageMappingProfile"; }
    }

    public DataStorageMappingProfile()
    {
        CreateMap<Infrastructure.MongoDb.Entities.Book, Domain.Models.BookModel>();
        CreateMap<Domain.Models.BookModel, Infrastructure.MongoDb.Entities.Book>();

        CreateMap<Infrastructure.MongoDb.Entities.Episode, Domain.Models.EpisodeModel>();
        CreateMap<Domain.Models.EpisodeModel, Infrastructure.MongoDb.Entities.Episode>();

        CreateMap<Infrastructure.MongoDb.Entities.Movie, Domain.Models.MovieModel>();
        CreateMap<Domain.Models.MovieModel, Infrastructure.MongoDb.Entities.Movie>();

        CreateMap<Infrastructure.MongoDb.Entities.MusicAlbum, Domain.Models.MusicAlbumModel>();
        CreateMap<Domain.Models.MusicAlbumModel, Infrastructure.MongoDb.Entities.MusicAlbum>();

        CreateMap<Infrastructure.MongoDb.Entities.TvShow, Domain.Models.TvShowModel>();
        CreateMap<Domain.Models.TvShowModel, Infrastructure.MongoDb.Entities.TvShow>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>();
        CreateMap<Domain.Models.VideoGameModel, Infrastructure.MongoDb.Entities.VideoGame>();

        CreateMap<Infrastructure.MongoDb.Entities.ReferenceEpisode, Domain.Models.ReferenceEpisodeModel>();
        CreateMap<Domain.Models.ReferenceEpisodeModel, Infrastructure.MongoDb.Entities.ReferenceEpisode>();

        CreateMap<Infrastructure.MongoDb.Entities.TvShowReference, Domain.Models.TvShowReferenceModel>();
        CreateMap<Domain.Models.TvShowReferenceModel, Infrastructure.MongoDb.Entities.TvShowReference>();

        CreateMap<Infrastructure.MongoDb.Entities.MovieReference, Domain.Models.MovieReferenceModel>();
        CreateMap<Domain.Models.MovieReferenceModel, Infrastructure.MongoDb.Entities.MovieReference>();

        CreateMap<DateTime, DateOnly>().ConvertUsing(dt => DateOnly.FromDateTime(dt));
        CreateMap<DateOnly, DateTime>().ConvertUsing(d => d.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
    }
}
