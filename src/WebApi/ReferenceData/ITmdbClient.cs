using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One TMDB search hit - title, year and a short synopsis, enough for automatic matching or for an
/// admin to pick from when a match is ambiguous.
/// </summary>
public record TmdbSearchResult(string TmdbId, string Title, int? Year, string? Synopsis, string? PosterUrl);

public record TmdbEpisode(int SeasonNumber, int EpisodeNumber, string Title, DateOnly? AirDate);

public record TmdbTvShowDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<TmdbEpisode> Episodes, List<string> Genres, string? PosterUrl);

public record TmdbMovieDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<string> Genres, string? PosterUrl);

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
}
