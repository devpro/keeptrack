using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// TMDB credits routinely list dozens of cast members; only the top-billed cast is shown on a
    /// show/movie page, so only that many are fetched into the reference document.
    /// </summary>
    private const int MaxCastMembers = 15;

    /// <summary>
    /// User-triggered "check for reference match" - looks only at the local reference collection (title+year,
    /// falling back to title-only, against every (title, year) combination ever confirmed for that reference -
    /// see <see cref="TvShowReferenceModel.MatchedAliases"/>), never TMDB. Cheap enough to run on demand from a
    /// detail page: no HTTP call, just an indexed Mongo lookup. Deliberately does NOT short-circuit when the
    /// model already has a link: the whole point is to let a tenant who isn't happy with the current match
    /// fix the title/year and re-check, replacing a wrong link - "don't guess" only applies to inventing a
    /// match from nothing, not to re-verifying one the tenant explicitly asked to redo. Updates only this
    /// tenant's own document directly (not the broad cross-tenant <see cref="ITvShowRepository.SetReferenceLinkAsync"/>,
    /// which refuses to touch already-linked documents by design), but still calls that method with the
    /// pre-edit title/year afterward so any other still-unresolved tenant sharing that text benefits too.
    /// A successful match also sets <see cref="TvShowModel.Year"/> to the reference's own canonical year
    /// (when it has one) - the tenant can still edit it afterward, but it's better pre-populated with a
    /// trustworthy value than left at whatever the tenant originally guessed. If no match is found for the
    /// current title/year and the document WAS linked, the link is cleared rather than left pointing at
    /// something the tenant just told us (by editing the title) is wrong - clearing <c>ReferenceId</c> is
    /// also exactly what puts it back into the admin's unresolved queue
    /// (<see cref="ITvShowRepository.FindDistinctUnresolvedTitleYearsAsync"/>) for a manual TMDB search.
    /// </summary>
    public async Task<TvShowModel> TryLinkExistingTvShowReferenceAsync(TvShowModel model)
    {
        // an empty title can never match anything, and falling through would wrongly unlink an
        // already-linked item - empty input must be a no-op, not an action
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

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
        if (reference.Year is not null) model.Year = reference.Year;
        await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await tvShowRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year);

        return model;
    }

    /// <summary>
    /// Movie equivalent of <see cref="TryLinkExistingTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<MovieModel> TryLinkExistingMovieReferenceAsync(MovieModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

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
        if (reference.Year is not null) model.Year = reference.Year;
        await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await movieRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year);

        return model;
    }

    /// <summary>
    /// Best-effort automatic match: does nothing if the search returns zero or more than one candidate,
    /// leaving the show unresolved for the admin queue instead of guessing.
    /// </summary>
    public async Task TryAutoResolveTvShowAsync(string title, int? year)
    {
        // never call the provider with an empty title - there is nothing to search with
        if (string.IsNullOrWhiteSpace(title)) return;

        var candidates = await tmdbClient.SearchTvShowAsync(title, year);
        if (candidates.Count != 1) return;
        await ResolveTvShowAsync(title, year, candidates[0].TmdbId);
    }

    /// <summary>
    /// Best-effort automatic match for movies - see <see cref="TryAutoResolveTvShowAsync"/>.
    /// </summary>
    public async Task TryAutoResolveMovieAsync(string title, int? year)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

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
        ArgumentException.ThrowIfNullOrWhiteSpace(title); // mapped to a 400 by ApiExceptionFilterAttribute

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
            // remembers both the canonical (TMDB title, TMDB year) and whatever (title, year) the tenant
            // actually searched with - see MatchedAliases: this is what lets a later, differently-titled or
            // differently-dated tenant match instantly
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null), (title, year, null)),
            Episodes = details.Episodes
                .Select(e => new ReferenceEpisodeModel { SeasonNumber = e.SeasonNumber, EpisodeNumber = e.EpisodeNumber, Title = e.Title, AirDate = e.AirDate })
                .ToList(),
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            ImageUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await tvShowReferenceRepository.UpsertAsync(model);
        await tvShowRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year);
        return saved;
    }

    /// <summary>
    /// Movie equivalent of <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<MovieReferenceModel> ResolveMovieAsync(string title, int? year, string tmdbId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

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
            // remembers both the canonical (TMDB title, TMDB year) and whatever (title, year) the tenant
            // actually searched with - see MatchedAliases: this is what lets a later, differently-titled or
            // differently-dated tenant match instantly
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null), (title, year, null)),
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            ImageUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await movieReferenceRepository.UpsertAsync(model);
        await movieRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year);
        return saved;
    }

    /// <summary>
    /// Re-fetches a TV show reference from TMDB if anything has changed since <see cref="TvShowReferenceModel.LastEnrichedAt"/>
    /// (skipping the expensive per-season episode fan-out when it hasn't), and always bumps <c>LastEnrichedAt</c>
    /// so the periodic sync doesn't keep re-checking an up-to-date document every run. A no-op (returns
    /// unchanged) for a reference with no TMDB id or that TMDB no longer has details for.
    /// </summary>
    public async Task<(TvShowReferenceModel Model, bool DataChanged)> RefreshTvShowReferenceAsync(TvShowReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var tmdbId = reference.ExternalIds.GetValueOrDefault("tmdb");
        if (string.IsNullOrEmpty(tmdbId)) return (reference, false);

        if (reference.LastEnrichedAt is not null)
        {
            var changed = await tmdbClient.HasTvShowChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                reference.LastEnrichedAt = DateTime.UtcNow;
                return (await tvShowReferenceRepository.UpsertAsync(reference), false);
            }
        }

        var details = await tmdbClient.GetTvShowDetailsAsync(tmdbId, cancellationToken);
        if (details is null) return (reference, false);
        var cast = await tmdbClient.GetTvShowCastAsync(tmdbId, cancellationToken);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        reference.Episodes = details.Episodes
            .Select(e => new ReferenceEpisodeModel { SeasonNumber = e.SeasonNumber, EpisodeNumber = e.EpisodeNumber, Title = e.Title, AirDate = e.AirDate })
            .ToList();
        reference.Genres = details.Genres;
        reference.Cast = await ResolveCastAsync(cast);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        return (await tvShowReferenceRepository.UpsertAsync(reference), true);
    }

    /// <summary>
    /// Movie equivalent of <see cref="RefreshTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<(MovieReferenceModel Model, bool DataChanged)> RefreshMovieReferenceAsync(MovieReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var tmdbId = reference.ExternalIds.GetValueOrDefault("tmdb");
        if (string.IsNullOrEmpty(tmdbId)) return (reference, false);

        if (reference.LastEnrichedAt is not null)
        {
            var changed = await tmdbClient.HasMovieChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                reference.LastEnrichedAt = DateTime.UtcNow;
                return (await movieReferenceRepository.UpsertAsync(reference), false);
            }
        }

        var details = await tmdbClient.GetMovieDetailsAsync(tmdbId, cancellationToken);
        if (details is null) return (reference, false);
        var cast = await tmdbClient.GetMovieCastAsync(tmdbId, cancellationToken);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        reference.Genres = details.Genres;
        reference.Cast = await ResolveCastAsync(cast);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        return (await movieReferenceRepository.UpsertAsync(reference), true);
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
            var personReferenceId = await ResolvePersonReferenceIdAsync("tmdb", member.PersonTmdbId, member.Name, member.ProfileImageUrl);
            result.Add(new CastMemberModel { PersonReferenceId = personReferenceId, CharacterName = member.CharacterName, Order = member.Order });
        }

        return result;
    }
}
