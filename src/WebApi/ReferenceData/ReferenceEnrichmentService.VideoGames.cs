using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// User-triggered "check for reference match" for video games - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>videogame_reference</c>). A successful match also sets
    /// <see cref="VideoGameModel.Year"/> to the reference's canonical year. <see cref="VideoGameModel.Platform"/>/
    /// <see cref="VideoGameModel.State"/> are never overwritten - they describe this tenant's own copy/progress.
    /// </summary>
    public async Task<VideoGameModel> TryLinkExistingVideoGameReferenceAsync(VideoGameModel model)
    {
        var reference = await videoGameReferenceRepository.FindByTitleYearAsync(model.Title, model.Year)
                        ?? await videoGameReferenceRepository.FindByTitleAsync(model.Title);

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await videoGameRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year);

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for video games - see <see cref="TryAutoResolveTvShowAsync"/>.
    /// </summary>
    public async Task TryAutoResolveVideoGameAsync(string title, int? year)
    {
        var candidates = await rawgClient.SearchGamesAsync(title, year);
        if (candidates.Count != 1) return;
        await ResolveVideoGameAsync(title, year, candidates[0].ExternalId);
    }

    /// <summary>
    /// Resolves a title+year to a specific RAWG game id, upserts the reference document, and propagates
    /// the link - see <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<VideoGameReferenceModel> ResolveVideoGameAsync(string title, int? year, string externalId)
    {
        var details = await rawgClient.GetGameDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"RAWG game {externalId} could not be fetched.");

        var existing = await videoGameReferenceRepository.FindByExternalIdAsync("rawg", externalId)
                       ?? await videoGameReferenceRepository.FindByTitleYearAsync(title, year)
                       ?? await videoGameReferenceRepository.FindByTitleAsync(title);
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["rawg"] = externalId;

        var model = new VideoGameReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            Platforms = details.Platforms,
            ExternalIds = externalIds,
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null), (title, year, null)),
            Genres = details.Genres,
            ImageUrl = details.ImageUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await videoGameReferenceRepository.UpsertAsync(model);
        await videoGameRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year);
        return saved;
    }

    /// <summary>
    /// Re-fetches a video game reference from RAWG, always doing a full re-fetch when called (unlike TMDB,
    /// RAWG exposes no per-id "has this changed" endpoint) - see <see cref="RefreshTvShowReferenceAsync"/>
    /// for the shared staleness-cutoff mechanism this is invoked from. A no-op (returns unchanged) for a
    /// reference with no RAWG id or that RAWG no longer has details for.
    /// </summary>
    public async Task<(VideoGameReferenceModel Model, bool DataChanged)> RefreshVideoGameReferenceAsync(VideoGameReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var externalId = reference.ExternalIds.GetValueOrDefault("rawg");
        if (string.IsNullOrEmpty(externalId)) return (reference, false);

        var details = await rawgClient.GetGameDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        reference.Platforms = details.Platforms;
        reference.Genres = details.Genres;
        reference.ImageUrl = details.ImageUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        return (await videoGameReferenceRepository.UpsertAsync(reference), true);
    }
}
