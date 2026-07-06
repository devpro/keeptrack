using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One TMDB search hit - title, year and a short synopsis, enough for automatic matching or for an
/// admin to pick from when a match is ambiguous.
/// </summary>
public record TmdbSearchResult(string TmdbId, string Title, int? Year, string? Synopsis);

public record TmdbEpisode(int SeasonNumber, int EpisodeNumber, string Title, DateOnly? AirDate);

public record TmdbTvShowDetails(string TmdbId, string Title, int? Year, string? Synopsis, List<TmdbEpisode> Episodes);

public record TmdbMovieDetails(string TmdbId, string Title, int? Year, string? Synopsis);

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
}
