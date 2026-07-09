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

        CreateMap<HouseDto, Domain.Models.HouseModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.HouseModel, HouseDto>();

        CreateMap<HouseHistoryDto, Domain.Models.HouseHistoryModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.HouseHistoryModel, HouseHistoryDto>();

        CreateMap<EpisodeDto, Domain.Models.EpisodeModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.EpisodeModel, EpisodeDto>();

        CreateMap<MovieDto, Domain.Models.MovieModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.MovieModel, MovieDto>();

        CreateMap<AlbumDto, Domain.Models.AlbumModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.AlbumModel, AlbumDto>();

        CreateMap<TvShowDto, Domain.Models.TvShowModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.TvShowModel, TvShowDto>();

        CreateMap<SongDto, Domain.Models.SongModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.SongModel, SongDto>();

        CreateMap<PlaylistDto, Domain.Models.PlaylistModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.PlaylistModel, PlaylistDto>();

        CreateMap<VideoGameDto, Domain.Models.VideoGameModel>()
            .ForMember(x => x.OwnerId, opt => opt.Ignore());
        CreateMap<Domain.Models.VideoGameModel, VideoGameDto>();

        CreateMap<PlaythroughDto, Domain.Models.PlaythroughModel>();
        CreateMap<Domain.Models.PlaythroughModel, PlaythroughDto>();

        CreateMap<VideoGamePlatformDto, Domain.Models.VideoGamePlatformModel>();
        CreateMap<Domain.Models.VideoGamePlatformModel, VideoGamePlatformDto>();

        // WatchNext reads are one-directional (Model -> Dto): WatchNextService is a pure Domain-level
        // computation with no Dto dependency, so WatchNextController maps its result here.
        CreateMap<Domain.Models.InProgressShowModel, InProgressShowDto>();

        // Car metrics reads are one-directional (Model -> Dto), same reasoning as WatchNext above:
        // CarMetricsService is a pure Domain-level computation with no Dto dependency.
        // NextMaintenance needs AllowNull() for the same reason ReferenceMatchModel.Creator does (see
        // Program.cs's AllowNullDestinationValues = false): without it, a null NextMaintenance model (no
        // maintenance recorded yet) maps to a new, all-default NextMaintenanceDto instead of staying null -
        // caught by CarResourceTest against a real car with no history, not by a mocked unit test.
        CreateMap<Domain.Models.CarMetricsModel, CarMetricsDto>()
            .ForMember(x => x.NextMaintenance, opt => opt.AllowNull());
        CreateMap<Domain.Models.ConsumptionPointModel, ConsumptionPointDto>();
        CreateMap<Domain.Models.CarCostHistoryPointModel, CarCostHistoryPointDto>();
        CreateMap<Domain.Models.CarMileageWarningModel, CarMileageWarningDto>();
        CreateMap<Domain.Models.NextMaintenanceModel, NextMaintenanceDto>();

        // House metrics reads are one-directional (Model -> Dto), same reasoning as Car metrics above:
        // HouseMetricsService is a pure Domain-level computation with no Dto dependency.
        CreateMap<Domain.Models.HouseMetricsModel, HouseMetricsDto>();
        CreateMap<Domain.Models.HouseCostHistoryPointModel, HouseCostHistoryPointDto>();
        CreateMap<Domain.Models.HouseCategoryCostModel, HouseCategoryCostDto>();

        // Reference-data reads are one-directional (Model -> Dto): admins submit a LinkReferenceRequestDto,
        // never a full TvShowReferenceDto/MovieReferenceDto, so there's no Dto -> Model direction to map.
        CreateMap<Domain.Models.ReferenceEpisodeModel, ReferenceEpisodeDto>();
        CreateMap<Domain.Models.ReferenceTrackModel, ReferenceTrackDto>();

        // Cast is ignored here and hydrated manually by ReferenceDataController: CastMemberModel only
        // carries a PersonReferenceId, while CastMemberDto needs the person's name/photo joined in from
        // person_reference - a join AutoMapper has no repository access to perform.
        CreateMap<Domain.Models.TvShowReferenceModel, TvShowReferenceDto>()
            .ForMember(x => x.Cast, opt => opt.Ignore());
        CreateMap<Domain.Models.MovieReferenceModel, MovieReferenceDto>()
            .ForMember(x => x.Cast, opt => opt.Ignore());

        // AuthorName/ArtistName are ignored here and hydrated manually by ReferenceDataController, same
        // reasoning as Cast above: the model only carries a *ReferenceId, the DTO needs the person's name
        // joined in from person_reference.
        CreateMap<Domain.Models.BookReferenceModel, BookReferenceDto>()
            .ForMember(x => x.AuthorName, opt => opt.Ignore())
            .ForMember(x => x.AuthorImageUrl, opt => opt.Ignore());
        CreateMap<Domain.Models.VideoGameReferenceModel, VideoGameReferenceDto>();
        CreateMap<Domain.Models.AlbumReferenceModel, AlbumReferenceDto>()
            .ForMember(x => x.ArtistName, opt => opt.Ignore())
            .ForMember(x => x.ArtistImageUrl, opt => opt.Ignore());
    }
}
