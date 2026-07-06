using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Resolves a show/movie title+year to a shared reference document and propagates its id to every
/// tenant's matching document. Shared by both the automatic (best-effort, background) path and the
/// admin manual-linking path so the "resolve and propagate" logic is never duplicated between them -
/// only how a TMDB id gets picked differs.
/// </summary>
public class ReferenceEnrichmentService(
    ITmdbClient tmdbClient,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository)
{
    /// <summary>
    /// Best-effort automatic match: does nothing if the search returns zero or more than one candidate,
    /// leaving the show unresolved for the admin queue instead of guessing.
    /// </summary>
    public async Task TryAutoResolveTvShowAsync(string title, int? year)
    {
        var candidates = await tmdbClient.SearchTvShowAsync(title, year);
        if (candidates.Count != 1) return;
        await ResolveTvShowAsync(title, year, candidates[0].TmdbId);
    }

    /// <summary>
    /// Best-effort automatic match for movies - see <see cref="TryAutoResolveTvShowAsync"/>.
    /// </summary>
    public async Task TryAutoResolveMovieAsync(string title, int? year)
    {
        var candidates = await tmdbClient.SearchMovieAsync(title, year);
        if (candidates.Count != 1) return;
        await ResolveMovieAsync(title, year, candidates[0].TmdbId);
    }

    /// <summary>
    /// Resolves a title+year to a specific TMDB show id (an admin's manual pick, or the single
    /// confident automatic match), upserts the reference document, and propagates the link.
    /// </summary>
    public async Task<TvShowReferenceModel> ResolveTvShowAsync(string title, int? year, string tmdbId)
    {
        var details = await tmdbClient.GetTvShowDetailsAsync(tmdbId)
                      ?? throw new InvalidOperationException($"TMDB show {tmdbId} could not be fetched.");

        var existing = await tvShowReferenceRepository.FindByTitleYearAsync(title, year);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;

        var model = new TvShowReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            ExternalIds = externalIds,
            Episodes = details.Episodes
                .Select(e => new ReferenceEpisodeModel { SeasonNumber = e.SeasonNumber, EpisodeNumber = e.EpisodeNumber, Title = e.Title, AirDate = e.AirDate })
                .ToList(),
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await tvShowReferenceRepository.UpsertAsync(model);
        await tvShowRepository.SetReferenceIdForTitleYearAsync(title, year, saved.Id!);
        return saved;
    }

    /// <summary>
    /// Movie equivalent of <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<MovieReferenceModel> ResolveMovieAsync(string title, int? year, string tmdbId)
    {
        var details = await tmdbClient.GetMovieDetailsAsync(tmdbId)
                      ?? throw new InvalidOperationException($"TMDB movie {tmdbId} could not be fetched.");

        var existing = await movieReferenceRepository.FindByTitleYearAsync(title, year);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;

        var model = new MovieReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            ExternalIds = externalIds,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await movieReferenceRepository.UpsertAsync(model);
        await movieRepository.SetReferenceIdForTitleYearAsync(title, year, saved.Id!);
        return saved;
    }
}
