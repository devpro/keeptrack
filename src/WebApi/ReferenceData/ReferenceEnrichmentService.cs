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
    /// User-triggered "check for reference match" - looks only at the local reference collection (title+year,
    /// falling back to title-only, against every title ever confirmed for that reference - see
    /// <see cref="TvShowReferenceModel.MatchedTitles"/>), never TMDB. Cheap enough to run on demand from a
    /// detail page: no HTTP call, just an indexed Mongo lookup. Deliberately does NOT short-circuit when the
    /// model already has a link: the whole point is to let a tenant who isn't happy with the current match
    /// fix the title/year and re-check, replacing a wrong link - "don't guess" only applies to inventing a
    /// match from nothing, not to re-verifying one the tenant explicitly asked to redo. Updates only this
    /// tenant's own document directly (not the broad cross-tenant <see cref="ITvShowRepository.SetReferenceLinkAsync"/>,
    /// which refuses to touch already-linked documents by design), but still calls that method with the
    /// pre-edit title/year afterward so any other still-unresolved tenant sharing that text benefits too.
    /// If no match is found for the current title/year and the document WAS linked, the link is cleared
    /// rather than left pointing at something the tenant just told us (by editing the title) is wrong -
    /// clearing <c>ReferenceId</c> is also exactly what puts it back into the admin's unresolved queue
    /// (<see cref="ITvShowRepository.FindDistinctUnresolvedTitleYearsAsync"/>) for a manual TMDB search.
    /// </summary>
    public async Task<TvShowModel> TryLinkExistingTvShowReferenceAsync(TvShowModel model)
    {
        var reference = await tvShowReferenceRepository.FindByTitleYearAsync(model.Title, model.Year)
                        ?? await tvShowReferenceRepository.FindByTitleAsync(model.Title);

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await tvShowRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title);

        return model;
    }

    /// <summary>
    /// Movie equivalent of <see cref="TryLinkExistingTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<MovieModel> TryLinkExistingMovieReferenceAsync(MovieModel model)
    {
        var reference = await movieReferenceRepository.FindByTitleYearAsync(model.Title, model.Year)
                        ?? await movieReferenceRepository.FindByTitleAsync(model.Title);

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await movieRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title);

        return model;
    }

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

        // tmdbId is checked first and is authoritative: two tenants resolving the exact same TMDB show under
        // different title text (a translation, a typo an admin corrected) must reuse the same reference
        // document, not create a duplicate - title/year matching alone can't guarantee that, only the id can.
        var existing = await tvShowReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await tvShowReferenceRepository.FindByTitleYearAsync(title, year)
                       ?? await tvShowReferenceRepository.FindByTitleAsync(title);
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
            // remembers both the canonical TMDB title and whatever text the tenant actually searched with -
            // see MatchedTitles: this is what lets a later, differently-titled tenant match instantly
            MatchedTitles = MergeMatchedTitles(existing?.MatchedTitles, details.Title, title),
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

        // tmdbId is checked first and is authoritative: two tenants resolving the exact same TMDB movie under
        // different title text (a translation, a typo an admin corrected) must reuse the same reference
        // document, not create a duplicate - title/year matching alone can't guarantee that, only the id can.
        var existing = await movieReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await movieReferenceRepository.FindByTitleYearAsync(title, year)
                       ?? await movieReferenceRepository.FindByTitleAsync(title);
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
            // remembers both the canonical TMDB title and whatever text the tenant actually searched with -
            // see MatchedTitles: this is what lets a later, differently-titled tenant match instantly
            MatchedTitles = MergeMatchedTitles(existing?.MatchedTitles, details.Title, title),
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
    /// Combines whatever title variants a reference document already remembered with the two new ones this
    /// resolution just confirmed: the TMDB canonical name and the text the tenant actually searched with (which
    /// may be a typo, a translation, or otherwise differ from canonical). Deduplicated and normalized.
    /// </summary>
    private static List<string> MergeMatchedTitles(List<string>? existing, string canonicalTitle, string searchedTitle)
    {
        var titles = new List<string>(existing ?? []);
        foreach (var title in new[] { canonicalTitle, searchedTitle })
        {
            var normalized = TitleNormalizer.Normalize(title);
            if (!titles.Contains(normalized)) titles.Add(normalized);
        }

        return titles;
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
