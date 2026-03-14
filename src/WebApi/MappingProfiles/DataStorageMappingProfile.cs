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

        CreateMap<Infrastructure.MongoDb.Entities.TvShow, Domain.Models.TvShowModel>();
        CreateMap<Domain.Models.TvShowModel, Infrastructure.MongoDb.Entities.TvShow>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>();
        CreateMap<Domain.Models.VideoGameModel, Infrastructure.MongoDb.Entities.VideoGame>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>();
        CreateMap<Domain.Models.VideoGameModel, Infrastructure.MongoDb.Entities.VideoGame>();

        CreateMap<Infrastructure.MongoDb.Entities.MusicAlbum, Domain.Models.MusicAlbumModel>();
        CreateMap<Domain.Models.MusicAlbumModel, Infrastructure.MongoDb.Entities.MusicAlbum>();

        CreateMap<DateTime, DateOnly>().ConvertUsing(dt => DateOnly.FromDateTime(dt));
        CreateMap<DateOnly, DateTime>().ConvertUsing(d => d.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
    }
}
