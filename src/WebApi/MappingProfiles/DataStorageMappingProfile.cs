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

        CreateMap<Infrastructure.MongoDb.Entities.Movie, Domain.Models.MovieModel>()
            .ForMember(x => x.AllocineId, opt => opt.MapFrom(
                x => x.Allocine != null ? x.Allocine.Id : null))
            .ForMember(x => x.ImdbPageId, opt => opt.MapFrom(
                x => x.Imdb != null ? x.Imdb.PageId : null));

        CreateMap<Domain.Models.MovieModel, Infrastructure.MongoDb.Entities.Movie>()
            .ForMember(x => x.Allocine, opt => opt.MapFrom(
                x => !string.IsNullOrEmpty(x.AllocineId) ? new Infrastructure.MongoDb.Entities.Allocine { Id = x.AllocineId } : null))
            .ForMember(x => x.Imdb, opt => opt.MapFrom(
                x => !string.IsNullOrEmpty(x.ImdbPageId) ? new Infrastructure.MongoDb.Entities.Imdb { PageId = x.ImdbPageId } : null));

        CreateMap<Infrastructure.MongoDb.Entities.MusicAlbum, Domain.Models.MusicAlbumModel>();
        CreateMap<Domain.Models.MusicAlbumModel, Infrastructure.MongoDb.Entities.MusicAlbum>();

        CreateMap<Infrastructure.MongoDb.Entities.TvShow, Domain.Models.TvShowModel>()
            .ForMember(x => x.AllocineId, opt => opt.MapFrom(
                x => x.Allocine != null ? x.Allocine.Id : null))
            .ForMember(x => x.ImdbPageId, opt => opt.MapFrom(
                x => x.Imdb != null ? x.Imdb.PageId : null));

        CreateMap<Domain.Models.TvShowModel, Infrastructure.MongoDb.Entities.TvShow>()
            .ForMember(x => x.Allocine, opt => opt.MapFrom(
                x => !string.IsNullOrEmpty(x.AllocineId) ? new Infrastructure.MongoDb.Entities.Allocine { Id = x.AllocineId } : null))
            .ForMember(x => x.Imdb, opt => opt.MapFrom(
                x => !string.IsNullOrEmpty(x.ImdbPageId) ? new Infrastructure.MongoDb.Entities.Imdb { PageId = x.ImdbPageId } : null));

        CreateMap<Infrastructure.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>();
        CreateMap<Domain.Models.VideoGameModel, Infrastructure.MongoDb.Entities.VideoGame>();

        CreateMap<DateTime, DateOnly>().ConvertUsing(dt => DateOnly.FromDateTime(dt));
        CreateMap<DateOnly, DateTime>().ConvertUsing(d => d.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
    }
}
