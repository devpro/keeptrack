using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One TMDB search hit: title, year and a short synopsis, enough for automatic matching or for an admin to pick from.
/// </summary>
public record TmdbSearchResult(string TmdbId, string Title, int? Year, string? Synopsis, string? PosterUrl) : IReferenceSearchCandidate;

/// <summary>
/// One entry of a TMDB "top rated" list: a search hit's fields plus TMDB's vote average (0 to 10), which Explore ranks and displays, and the title's page on themoviedb.org.
/// </summary>
public record TmdbTopRatedItem(string TmdbId, string Title, int? Year, string? Synopsis, string? PosterUrl, double? VoteAverage, string? WebUrl);

public record TmdbEpisode(int SeasonNumber, int EpisodeNumber, string Title, DateOnly? AirDate);

public record TmdbTvShowDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<TmdbEpisode> Episodes, List<string> Genres, string? PosterUrl, double? VoteAverage = null, int? VoteCount = null, string? ImdbId = null);

public record TmdbMovieDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<string> Genres, string? PosterUrl, double? VoteAverage, int? VoteCount, string? ImdbId = null);

/// <summary>
/// One credited cast member, whose <see cref="PersonTmdbId"/> deduplicates the actor across every work crediting them (see <c>PersonReferenceModel</c>).
/// </summary>
public record TmdbCastMember(string PersonTmdbId, string Name, string CharacterName, int Order, string? ProfileImageUrl);

/// <summary>
/// Thin wrapper over the TMDB REST API, an interface so tests use a fake.
/// </summary>
public interface ITmdbClient
{
    Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default);

    /// <summary>
    /// One page (about 20) of TMDB's top-rated movies, best first, the source of Explore.
    /// It comes from the provider rather than the local references, so it surfaces acclaimed titles nobody tracks yet.
    /// </summary>
    Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedMoviesAsync(int page, CancellationToken cancellationToken = default);

    /// <summary>TV equivalent of <see cref="GetTopRatedMoviesAsync"/>.</summary>
    Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedTvShowsAsync(int page, CancellationToken cancellationToken = default);

    Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether TMDB recorded any change to this show since <paramref name="since"/>, one cheap call letting the sync skip unchanged shows.
    /// </summary>
    Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default);

    /// <summary>
    /// Movie equivalent of <see cref="HasTvShowChangedSinceAsync"/>.
    /// </summary>
    Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default);

    /// <summary>
    /// A show's IMDb id through <c>/tv/{id}/external_ids</c>, one cheap call,
    /// so a reference missing it backfills the id and then its rating without the full fetch the no-change shortcut avoids.
    /// </summary>
    Task<string?> GetTvShowImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Movie equivalent of <see cref="GetTvShowImdbIdAsync"/> (<c>/movie/{id}/external_ids</c>).
    /// </summary>
    Task<string?> GetMovieImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default);
}
