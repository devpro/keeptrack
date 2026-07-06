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
    IPersonReferenceRepository personReferenceRepository,
    ITvShowRepository tvShowRepository,
    IMovieRepository movieRepository)
{
    /// <summary>
    /// TMDB credits routinely list dozens of cast members; only the top-billed cast is shown on a
    /// show/movie page, so only that many are fetched into the reference document.
    /// </summary>
    private const int MaxCastMembers = 15;

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
        var cast = await tmdbClient.GetTvShowCastAsync(tmdbId);

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
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            PosterUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await tvShowReferenceRepository.UpsertAsync(model);
        await tvShowRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title);
        return saved;
    }

    /// <summary>
    /// Movie equivalent of <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<MovieReferenceModel> ResolveMovieAsync(string title, int? year, string tmdbId)
    {
        var details = await tmdbClient.GetMovieDetailsAsync(tmdbId)
                      ?? throw new InvalidOperationException($"TMDB movie {tmdbId} could not be fetched.");
        var cast = await tmdbClient.GetMovieCastAsync(tmdbId);

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
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            PosterUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await movieReferenceRepository.UpsertAsync(model);
        await movieRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title);
        return saved;
    }

    /// <summary>
    /// Upserts each cast member into the shared, owner-less person_reference collection (deduplicated by
    /// TMDB person id - the same actor credited in two different shows only ever gets one document), then
    /// returns the embedded cast list pointing at those documents.
    /// </summary>
    private async Task<List<CastMemberModel>> ResolveCastAsync(IReadOnlyList<TmdbCastMember> cast)
    {
        var result = new List<CastMemberModel>();

        foreach (var member in cast.OrderBy(c => c.Order).Take(MaxCastMembers))
        {
            var existingPerson = await personReferenceRepository.FindByExternalIdAsync("tmdb", member.PersonTmdbId);
            var person = new PersonReferenceModel
            {
                Id = existingPerson?.Id,
                Name = member.Name,
                ProfileImageUrl = member.ProfileImageUrl ?? existingPerson?.ProfileImageUrl,
                ExternalIds = existingPerson?.ExternalIds ?? new Dictionary<string, string> { ["tmdb"] = member.PersonTmdbId }
            };
            var savedPerson = await personReferenceRepository.UpsertAsync(person);

            result.Add(new CastMemberModel { PersonReferenceId = savedPerson.Id!, CharacterName = member.CharacterName, Order = member.Order });
        }

        return result;
    }
}
