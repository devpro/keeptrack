namespace KeepTrack.WebApi.MappingProfiles;

public class GenericMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeepTrackApiGenericMappingProfile"; }
    }

    public GenericMappingProfile()
    {
        CreateMap<MovieDto, Domain.Models.MovieModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.MovieModel, MovieDto>();

        CreateMap<CarHistoryDto, Domain.Models.CarHistoryModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.CarHistoryModel, CarHistoryDto>();

        CreateMap<BookDto, Domain.Models.BookModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.BookModel, BookDto>();

        CreateMap<TvShowDto, Domain.Models.TvShowModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.TvShowModel, TvShowDto>();

        CreateMap<VideoGameDto, Domain.Models.VideoGameModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.VideoGameModel, VideoGameDto>();
    }
}
