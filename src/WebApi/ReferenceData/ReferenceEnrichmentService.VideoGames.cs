using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// User-triggered "check for reference match" for video games - see
    /// <see cref="TryLinkExistingTvShowReferenceAsync"/> for the full rationale (this is the same local-only,
    /// no-HTTP-call lookup, just against <c>videogame_reference</c>). A successful match also sets
    /// <see cref="VideoGameModel.Year"/> to the reference's canonical year. <see cref="VideoGameModel.Platforms"/>
    /// is never touched - each entry describes this tenant's own copy/progress on that platform, not the
    /// canonical release.
    /// </summary>
    public async Task<VideoGameModel> TryLinkExistingVideoGameReferenceAsync(VideoGameModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // see TryLinkExistingTvShowReferenceAsync's own comment - the title-only fallback must not run when
        // the tenant has a specific year that simply has no confirmed alias
        var reference = await videoGameReferenceRepository.FindByTitleYearAsync(model.Title, model.Year);
        if (reference is null && model.Year is null)
        {
            reference = await videoGameReferenceRepository.FindByTitleAsync(model.Title);
        }

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                model.ReferenceRatingSource = null;
                await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await videoGameRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);

        return model;
    }

    /// <summary>
    /// Admin-triggered "unlink" for video games - see <see cref="UnlinkTvShowReferenceAsync"/> for the full
    /// rationale (clears the tenant's link and permanently deletes the shared reference document, rather
    /// than only detaching this one item).
    /// </summary>
    public async Task<VideoGameModel> UnlinkVideoGameReferenceAsync(VideoGameModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        model.ReferenceRatingSource = null;
        await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await videoGameReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for video games - see <see cref="TryAutoResolveTvShowAsync"/>. Always
    /// searches the deployment's *default* provider (<see cref="ReferenceClientRegistry{TClient}.Resolve"/>
    /// with a null key) - this is the unattended background path, so there's no admin picking a provider here.
    /// </summary>
    public async Task TryAutoResolveVideoGameAsync(string title, int? year)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        var client = videoGameReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchGamesAsync(title, year);
        if (candidates.Count != 1) return;
        await ResolveVideoGameAsync(title, year, candidates[0].ExternalId, client.ProviderKey);
    }

    /// <summary>
    /// Resolves a title+year to a specific provider's game id, upserts the reference document, and propagates
    /// the link - see <see cref="ResolveTvShowAsync"/>. <paramref name="providerKey"/> is which registered
    /// <see cref="IVideoGameReferenceClient"/> <paramref name="externalId"/> came from - required from the
    /// admin's manual link action (an id is meaningless without knowing which provider issued it once more
    /// than one is registered), defaults to the deployment default for the automatic path above.
    /// </summary>
    public async Task<VideoGameReferenceModel> ResolveVideoGameAsync(string title, int? year, string externalId, string? providerKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = videoGameReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetGameDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Video game {externalId} could not be fetched from {client.ProviderKey}.");

        // see ResolveTvShowAsync's own comment - the title-only fallback (which reuses existing.Id for the
        // upsert) must not run when year is known but simply unconfirmed yet, or it risks overwriting an
        // unrelated same-titled reference document instead of just linking wrong
        var existing = await videoGameReferenceRepository.FindByExternalIdAsync(client.ProviderKey, externalId)
                       ?? await videoGameReferenceRepository.FindByTitleYearAsync(title, year);
        if (existing is null && year is null)
        {
            existing = await videoGameReferenceRepository.FindByTitleAsync(title);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds[client.ProviderKey] = externalId;

        var model = new VideoGameReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            Platforms = details.Platforms,
            ExternalIds = externalIds,
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Genres = details.Genres,
            Ratings = MergeProviderRatings(existing?.Ratings, details.Ratings, client.SupportedRatingSources),
            ImageUrl = PreferredImageUrl(client.ProviderKey, externalIds, existing?.ImageUrl, details.ImageUrl),
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await videoGameReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, ratingValue, ratingScale, ratingSource);
        return saved;
    }

    /// <summary>
    /// Re-fetches a video game reference from the deployment's default provider, always doing a full re-fetch
    /// when called (unlike TMDB, neither RAWG nor IGDB exposes a per-id "has this changed" endpoint) - see
    /// <see cref="RefreshTvShowReferenceAsync"/> for the shared staleness-cutoff mechanism this is invoked from.
    /// A reference that doesn't carry the default provider's id yet gets one adopted first
    /// (<see cref="TryAdoptDefaultVideoGameProviderAsync"/>).
    /// <para>
    /// **Only the default provider is ever called**, which is the one place this deliberately diverges from
    /// <see cref="RefreshBookReferenceAsync"/>'s "refresh through whichever provider linked it". That rule is
    /// right for books, where every registered provider is reachable. Video games gained a second provider
    /// *because the first one went down*, so falling back to it means every not-yet-adopted reference pays a
    /// full retry-and-timeout cycle against a dead host on every pass - hundreds of doomed calls, for data
    /// that cannot come back. An operator who selects a provider should not see traffic to another one.
    /// </para>
    /// <para>
    /// A reference that can't be adopted is therefore left with the data it already has and simply stamped as
    /// checked. Stamping matters: <c>FindStaleAsync</c> serves the least-recently-enriched first under a
    /// per-pass cap, so a document that never has its <see cref="VideoGameReferenceModel.LastEnrichedAt"/>
    /// bumped would sit at the head of that queue forever and starve everything behind it - the same
    /// re-walking-the-same-head failure the cap's ordering exists to prevent.
    /// </para>
    /// </summary>
    public async Task<(VideoGameReferenceModel Model, bool DataChanged)> RefreshVideoGameReferenceAsync(VideoGameReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var client = videoGameReferenceClientRegistry.Resolve(null);
        await TryAdoptDefaultVideoGameProviderAsync(reference, client, cancellationToken);

        if (!reference.ExternalIds.TryGetValue(client.ProviderKey, out var externalId))
        {
            logger.LogInformation(
                "Video game reference {ReferenceId} ({Title}) carries no {Provider} id and could not adopt one; leaving its existing data and provider ids untouched.",
                reference.Id, reference.Title, client.ProviderKey);
            return (await StampCheckedAsync(reference), false);
        }

        var details = await client.GetGameDetailsAsync(externalId, cancellationToken);
        if (details is null) return (reference, false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        reference.Platforms = details.Platforms;
        reference.Genres = details.Genres;
        reference.Ratings = MergeProviderRatings(reference.Ratings, details.Ratings, client.SupportedRatingSources);
        reference.ImageUrl = PreferredImageUrl(client.ProviderKey, reference.ExternalIds, reference.ImageUrl, details.ImageUrl);
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await videoGameReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    /// <summary>
    /// Gives a reference that predates the current default provider one of that provider's ids, so it can be
    /// refreshed and rated through it like everything created since.
    /// <para>
    /// This is what carries a catalogue across a provider change without a migration script: references linked
    /// through the old provider would otherwise keep only its ratings forever, and show nothing at all once an
    /// admin selects a rating source only the new provider reports. It rides the sync's existing per-document
    /// loop, costs one search per not-yet-adopted reference per pass, and stops costing anything once adopted.
    /// </para>
    /// <para>
    /// The match rule is deliberately stricter than <see cref="TryAutoResolveVideoGameAsync"/>'s: exactly one
    /// candidate whose normalized title equals the reference's, with a compatible year. A reference's title and
    /// year are canonical provider data rather than tenant-typed text, so an exact match is a genuine
    /// confirmation - but two different games sharing a title is ordinary in this domain, so anything ambiguous
    /// is left for an admin to link by hand rather than guessed at.
    /// </para>
    /// </summary>
    private async Task TryAdoptDefaultVideoGameProviderAsync(VideoGameReferenceModel reference, IVideoGameReferenceClient client, CancellationToken cancellationToken)
    {
        if (reference.ExternalIds.ContainsKey(client.ProviderKey) || string.IsNullOrWhiteSpace(reference.Title)) return;

        var candidates = await client.SearchGamesAsync(reference.Title, reference.Year, cancellationToken);
        var normalizedTitle = TitleNormalizer.Normalize(reference.Title);
        var matches = candidates
            .Where(c => TitleNormalizer.Normalize(c.Title) == normalizedTitle)
            .Where(c => reference.Year is null || c.Year is null || c.Year == reference.Year)
            .ToList();

        if (matches.Count != 1)
        {
            // logged rather than silent: this is the whole reason a reference can stay on the old provider, and
            // without it "why is nothing adopting?" is invisible. The candidate titles are what actually
            // explains it - an ambiguous count usually means editions/DLC sharing a title, and zero usually
            // means the two providers disagree about the year.
            logger.LogInformation(
                "No unambiguous {Provider} match for video game reference {ReferenceId} \"{Title}\" ({Year}): {CandidateCount} candidate(s) [{Candidates}], {MatchCount} matching title+year.",
                client.ProviderKey, reference.Id, reference.Title, reference.Year, candidates.Count,
                string.Join(" | ", candidates.Select(c => $"{c.Title} ({c.Year})")), matches.Count);
            return;
        }

        logger.LogInformation(
            "Adopted {Provider} id {ExternalId} for video game reference {ReferenceId} \"{Title}\".",
            client.ProviderKey, matches[0].ExternalId, reference.Id, reference.Title);
        reference.ExternalIds[client.ProviderKey] = matches[0].ExternalId;
    }

    /// <summary>
    /// The image a video game reference keeps: whatever <paramref name="providerKey"/> just returned, except
    /// that a provider other than RAWG may not overwrite a stored image on a reference carrying a RAWG id.
    /// <para>
    /// RAWG's <c>background_image</c> is curated landscape key art, and its image CDN is still serving those
    /// URLs even though its API is not - so for a reference linked through RAWG the stored image is both good
    /// and still working. IGDB has no equivalent: its cover is portrait box art, its artwork is contributed and
    /// unreliable, and its screenshots are raw frames with HUD. Replacing a working RAWG image with any of
    /// those is a downgrade, and a refresh that downgrades data is not a refresh.
    /// </para>
    /// <para>
    /// It is also irreversible: the RAWG URL cannot be recomputed from the RAWG id without RAWG's API, so once
    /// overwritten it is gone. That asymmetry - a small cosmetic gain against permanent data loss - is what
    /// makes "keep what we have" the right default rather than a special case.
    /// </para>
    /// <para>
    /// <b>RAWG itself is exempt, and that half is load-bearing.</b> The rule keys on "this document carries a
    /// RAWG id", which is only a proxy for "the stored image is a RAWG image" - and the two diverge the moment
    /// a document holds both ids, which is the normal state after
    /// <see cref="TryAdoptDefaultVideoGameProviderAsync"/> has run. Without the exemption the guard fires
    /// against the very provider it exists to protect: an admin re-linking a reference through RAWG
    /// (<see cref="ReferenceDataAdminController"/> passes the picked provider straight through to
    /// <see cref="ResolveVideoGameAsync"/>) adds the RAWG id and then has the freshly fetched RAWG key art
    /// discarded in favour of the IGDB cover already stored - the exact inversion of the intent. It would also
    /// leave a dead RAWG URL unrepairable by any action short of unlinking, which deletes the shared reference
    /// document outright.
    /// </para>
    /// </summary>
    private static string? PreferredImageUrl(string providerKey, Dictionary<string, string> externalIds, string? existingImageUrl, string? fetchedImageUrl) =>
        providerKey != RatingSourceCatalog.Rawg
        && externalIds.ContainsKey(RatingSourceCatalog.Rawg)
        && !string.IsNullOrEmpty(existingImageUrl)
            ? existingImageUrl
            : fetchedImageUrl ?? existingImageUrl;

    /// <summary>
    /// Records that a reference was looked at during a pass without anything being fetched for it, so the
    /// staleness queue rotates past it - see <see cref="RefreshVideoGameReferenceAsync"/> for why that matters.
    /// </summary>
    private async Task<VideoGameReferenceModel> StampCheckedAsync(VideoGameReferenceModel reference)
    {
        reference.LastEnrichedAt = DateTime.UtcNow;
        return await videoGameReferenceRepository.UpsertAsync(reference);
    }
}
