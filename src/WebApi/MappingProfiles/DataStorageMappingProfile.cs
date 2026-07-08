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

        CreateMap<Infrastructure.MongoDb.Entities.Album, Domain.Models.AlbumModel>();
        CreateMap<Domain.Models.AlbumModel, Infrastructure.MongoDb.Entities.Album>();

        CreateMap<Infrastructure.MongoDb.Entities.TvShow, Domain.Models.TvShowModel>();
        CreateMap<Domain.Models.TvShowModel, Infrastructure.MongoDb.Entities.TvShow>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGame, Domain.Models.VideoGameModel>()
            .ForMember(x => x.Platform, opt => opt.Ignore())
            .ForMember(x => x.State, opt => opt.Ignore());
        CreateMap<Domain.Models.VideoGameModel, Infrastructure.MongoDb.Entities.VideoGame>();

        CreateMap<Infrastructure.MongoDb.Entities.Playthrough, Domain.Models.PlaythroughModel>();
        CreateMap<Domain.Models.PlaythroughModel, Infrastructure.MongoDb.Entities.Playthrough>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGamePlatform, Domain.Models.VideoGamePlatformModel>();
        CreateMap<Domain.Models.VideoGamePlatformModel, Infrastructure.MongoDb.Entities.VideoGamePlatform>();

        CreateMap<Infrastructure.MongoDb.Entities.ReferenceEpisode, Domain.Models.ReferenceEpisodeModel>();
        CreateMap<Domain.Models.ReferenceEpisodeModel, Infrastructure.MongoDb.Entities.ReferenceEpisode>();

        CreateMap<Infrastructure.MongoDb.Entities.ReferenceMatch, Domain.Models.ReferenceMatchModel>();

        // Creator has no creator dimension for TV show/movie/video game (always null there) - overriding
        // the profile-wide AllowNullDestinationValues = false (Program.cs) just for this member keeps a
        // null Creator stored as an actual BSON null instead of "", so the app never has to treat null and
        // "" as equivalent when comparing it (see ReferenceEnrichmentService.MergeMatchedAliases).
        CreateMap<Domain.Models.ReferenceMatchModel, Infrastructure.MongoDb.Entities.ReferenceMatch>()
            .ForMember(x => x.Creator, opt => opt.AllowNull());

        CreateMap<Infrastructure.MongoDb.Entities.TvShowReference, Domain.Models.TvShowReferenceModel>();
        CreateMap<Domain.Models.TvShowReferenceModel, Infrastructure.MongoDb.Entities.TvShowReference>();

        CreateMap<Infrastructure.MongoDb.Entities.MovieReference, Domain.Models.MovieReferenceModel>();
        CreateMap<Domain.Models.MovieReferenceModel, Infrastructure.MongoDb.Entities.MovieReference>();

        CreateMap<Infrastructure.MongoDb.Entities.BookReference, Domain.Models.BookReferenceModel>();
        CreateMap<Domain.Models.BookReferenceModel, Infrastructure.MongoDb.Entities.BookReference>();

        CreateMap<Infrastructure.MongoDb.Entities.VideoGameReference, Domain.Models.VideoGameReferenceModel>();
        CreateMap<Domain.Models.VideoGameReferenceModel, Infrastructure.MongoDb.Entities.VideoGameReference>();

        CreateMap<Infrastructure.MongoDb.Entities.AlbumReference, Domain.Models.AlbumReferenceModel>();
        CreateMap<Domain.Models.AlbumReferenceModel, Infrastructure.MongoDb.Entities.AlbumReference>();

        CreateMap<Infrastructure.MongoDb.Entities.CastMember, Domain.Models.CastMemberModel>();
        CreateMap<Domain.Models.CastMemberModel, Infrastructure.MongoDb.Entities.CastMember>();

        CreateMap<Infrastructure.MongoDb.Entities.PersonReference, Domain.Models.PersonReferenceModel>();
        CreateMap<Domain.Models.PersonReferenceModel, Infrastructure.MongoDb.Entities.PersonReference>();

        CreateMap<DateTime, DateOnly>().ConvertUsing(dt => DateOnly.FromDateTime(dt));
        CreateMap<DateOnly, DateTime>().ConvertUsing(d => d.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
    }
}
