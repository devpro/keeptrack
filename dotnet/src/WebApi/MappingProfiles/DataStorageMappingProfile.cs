namespace KeepTrack.WebApi.MappingProfiles;

public class DataStorageMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeepTrackDataStorageMappingProfile"; }
    }

    public DataStorageMappingProfile()
    {
        CreateMap<Dal.MongoDb.Entities.Book, Domain.Models.BookModel>();
        CreateMap<Domain.Models.BookModel, Dal.MongoDb.Entities.Book>();

        CreateMap<Dal.MongoDb.Entities.TvShow, Domain.Models.TvShowModel>();
        CreateMap<Domain.Models.TvShowModel, Dal.MongoDb.Entities.TvShow>();

        CreateMap<Dal.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>();
        CreateMap<Domain.Models.VideoGameModel, Dal.MongoDb.Entities.VideoGame>();
    }
}
