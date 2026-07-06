namespace Keeptrack.WebApi.MappingProfiles;

public class WebServiceMappingProfile : Profile
{
    public override string ProfileName
    {
        get { return "KeeptrackWebServiceMappingProfile"; }
    }

    public WebServiceMappingProfile()
    {
        CreateMap<BookDto, Domain.Models.BookModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.BookModel, BookDto>();

        CreateMap<CarDto, Domain.Models.CarModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.CarModel, CarDto>();

        CreateMap<CarHistoryDto, Domain.Models.CarHistoryModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.CarHistoryModel, CarHistoryDto>();

        CreateMap<EpisodeDto, Domain.Models.EpisodeModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.EpisodeModel, EpisodeDto>();

        CreateMap<MovieDto, Domain.Models.MovieModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.MovieModel, MovieDto>();

        CreateMap<MusicAlbumDto, Domain.Models.MusicAlbumModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.MusicAlbumModel, MusicAlbumDto>();

        CreateMap<TvShowDto, Domain.Models.TvShowModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.TvShowModel, TvShowDto>();

        CreateMap<VideoGameDto, Domain.Models.VideoGameModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.VideoGameModel, VideoGameDto>();

        // Reference-data reads are one-directional (Model -> Dto): admins submit a LinkReferenceRequestDto,
        // never a full TvShowReferenceDto/MovieReferenceDto, so there's no Dto -> Model direction to map.
        CreateMap<Domain.Models.ReferenceEpisodeModel, ReferenceEpisodeDto>();
        CreateMap<Domain.Models.TvShowReferenceModel, TvShowReferenceDto>();
        CreateMap<Domain.Models.MovieReferenceModel, MovieReferenceDto>();
    }
}
