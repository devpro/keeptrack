namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One TMDB search hit - title, year and a short synopsis, enough for automatic matching or for an
/// admin to pick from when a match is ambiguous.
/// </summary>
public record TmdbSearchResult(string TmdbId, string Title, int? Year, string? Synopsis, string? PosterUrl);

public record TmdbEpisode(int SeasonNumber, int EpisodeNumber, string Title, DateOnly? AirDate);

public record TmdbTvShowDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<TmdbEpisode> Episodes, List<string> Genres, string? PosterUrl, double? VoteAverage = null, int? VoteCount = null, string? ImdbId = null);

public record TmdbMovieDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<string> Genres, string? PosterUrl, double? VoteAverage, int? VoteCount, string? ImdbId = null);

/// <summary>
/// One credited cast member - <see cref="PersonTmdbId"/> is TMDB's person id, used to deduplicate
/// actors across every show/movie that credits them (see <c>PersonReferenceModel</c>).
/// </summary>
public record TmdbCastMember(string PersonTmdbId, string Name, string CharacterName, int Order, string? ProfileImageUrl);

/// <summary>
/// Thin wrapper over the TMDB REST API. Interface exists so tests use a fake - never call the real
/// TMDB API from a test.
/// </summary>
public interface ITmdbClient
{
    Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default);

    Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether TMDB has recorded any change to this show since <paramref name="since"/> - a cheap (one
    /// call, no season fan-out) pre-check the periodic reference sync uses to skip a full re-fetch of
    /// unchanged shows.
    /// </summary>
    Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default);

    /// <summary>
    /// Movie equivalent of <see cref="HasTvShowChangedSinceAsync"/>.
    /// </summary>
    Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default);

    /// <summary>
    /// A show's IMDb id via TMDB's dedicated <c>/tv/{id}/external_ids</c> endpoint - one cheap call, no season
    /// fan-out, so a reference enriched before IMDb ratings existed can backfill its imdb id (and then its
    /// rating) without the full details re-fetch the no-change sync short-circuit is meant to avoid.
    /// </summary>
    Task<string?> GetTvShowImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Movie equivalent of <see cref="GetTvShowImdbIdAsync"/> (<c>/movie/{id}/external_ids</c>).
    /// </summary>
    Task<string?> GetMovieImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default);
}
