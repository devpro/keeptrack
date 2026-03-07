namespace KeepTrack.WebApi.MappingProfiles;

public class MovieDataStorageMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeepTrackMovieDataStorageMappingProfile"; }
    }

    public MovieDataStorageMappingProfile()
    {
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
    }
}
