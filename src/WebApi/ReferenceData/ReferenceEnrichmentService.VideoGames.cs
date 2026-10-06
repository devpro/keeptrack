using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// How long a fruitless provider-id adoption attempt is remembered before it is worth asking again.
    /// Shorter than the rating re-attempt window, since the answer can change for an ordinary reason: the provider corrects a year, or adds the missing entry.
    /// Long enough that a reference the provider genuinely can't match stops costing two calls a day.
    /// </summary>
    private static readonly TimeSpan ProviderAdoptionReattemptAfter = TimeSpan.FromDays(7);

    /// <summary>
    /// The local-only half of "check for reference match" for video games, against <c>videogame_reference</c> (see <see cref="TryLinkExistingTvShowReferenceAsync"/>).
    /// A match also sets <see cref="VideoGameModel.Year"/> to the reference's canonical year.
    /// <see cref="VideoGameModel.Platforms"/> is never touched, since each entry describes the tenant's own copy and progress, not the canonical release.
    /// </summary>
    public async Task<VideoGameModel> TryLinkExistingVideoGameReferenceAsync(VideoGameModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // No title-only fallback, unlike the other domains: a year is required for any automatic link here (see TryAutoResolveVideoGameAsync).
        // The fallback serves a tenant who recorded no year, and for video games that tenant must not be linked to a title's first namesake.
        var reference = await videoGameReferenceRepository.FindByTitleYearAsync(model.Title, model.Year);

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

        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await videoGameRepository.UpdateAsync(model.Id!, model, model.OwnerId);

        return model;
    }

    /// <summary>
    /// "Check for reference match" for video games: an established local match first, else the default provider under the rule of automatic resolution (see <see cref="LinkTvShowReferenceAsync"/>).
    /// <para>
    /// It links exactly what <see cref="TryAutoResolveVideoGameAsync"/> would have on create, so a title with namesakes and no year still resolves to nothing.
    /// What it adds is a second chance once the tenant has supplied the year, otherwise only available by creating the item again.
    /// </para>
    /// </summary>
    public async Task<VideoGameModel> LinkVideoGameReferenceAsync(VideoGameModel model)
    {
        model = await TryLinkExistingVideoGameReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        // resolution writes the link to the stored item, so the caller's copy is read again
        await TryAutoResolveVideoGameAsync(model);
        return await videoGameRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>
    /// Admin "unlink" for video games: clears the tenant's link and permanently deletes the shared reference document (see <see cref="UnlinkTvShowReferenceAsync"/>).
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
    /// Best-effort automatic match for video games (see <see cref="TryAutoResolveTvShowAsync"/>).
    /// It always searches the deployment's default provider (<see cref="ReferenceClientRegistry{TClient}.Resolve"/> with a null key), since no admin picks a provider on this unattended path.
    /// <para>
    /// Confident means <see cref="ReferenceMatchRules.ConfirmedMatches"/>: a single candidate actually named this game and agreeing about the year.
    /// It is <b>not</b> "the provider returned exactly one result", which reads a property of the search as a property of the answer, and is wrong both ways.
    /// IGDB answers "NieR:Automata" with a single "Untitled NieR:Automata Project", which row counting would link without comparing titles.
    /// IGDB also holds eight games named "Resident Evil 2", and row counting would never link the 2019 remake, though only one of the eight is from 2019.
    /// </para>
    /// <para>
    /// A title the provider spells differently lands in the admin queue instead of linking to whatever the search returned.
    /// A queue entry is one click, while a wrong link is silent data loss.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveVideoGameAsync(VideoGameModel item)
    {
        var title = item.Title;
        var year = item.Year;

        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        // A year is required for any automatic link in this domain (owner's rule).
        // Video game catalogues are full of same-titled works, so a title alone identifies nothing.
        // Without a year the item waits, and "check for reference match" resolves it once a year is filled in.
        if (year is null) return;

        // a reference already confirmed for this exact (title, year) is the answer, asked before the provider (see TryLinkKnownReferenceAsync)
        if (await TryLinkKnownReferenceAsync(
                () => videoGameReferenceRepository.FindByTitleYearAsync(title, year),
                reference => WriteVideoGameLinkAsync(reference, ReferenceLinkTarget.Item(item.Id!, item.OwnerId))))
        {
            return;
        }

        var client = videoGameReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchGamesAsync(title, year);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveVideoGameAsync(title, year, matches[0].ExternalId, ReferenceLinkTarget.Item(item.Id!, item.OwnerId), client.ProviderKey);
    }

    /// <summary>
    /// Resolves a title and year to a provider's game id, upserts the reference document, and links the records <paramref name="target"/> names (see <see cref="ResolveTvShowAsync"/>).
    /// <paramref name="providerKey"/> names the registered <see cref="IVideoGameReferenceClient"/> that issued <paramref name="externalId"/>.
    /// The admin's manual link passes it, since an id means nothing without its provider, and the automatic path falls back to the deployment default.
    /// </summary>
    public async Task<VideoGameReferenceModel> ResolveVideoGameAsync(string title, int? year, string externalId, ReferenceLinkTarget target, string? providerKey = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var client = videoGameReferenceClientRegistry.Resolve(providerKey);
        var details = await client.GetGameDetailsAsync(externalId)
                      ?? throw new InvalidOperationException($"Video game {externalId} could not be fetched from {client.ProviderKey}.");

        // The title-only fallback reuses existing.Id for the upsert, so it must not run when the year is known (see ResolveTvShowAsync).
        // It would otherwise overwrite an unrelated same-titled reference document.
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
            MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Genres = details.Genres,
            Ratings = MergeProviderRatings(existing?.Ratings, details.Ratings, client.SupportedRatingSources),
            ImageUrl = PreferredImageUrl(client.ProviderKey, externalIds, existing?.ImageUrl, details.ImageUrl),
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await videoGameReferenceRepository.UpsertAsync(model);
        await WriteVideoGameLinkAsync(saved, target);
        return saved;
    }

    /// <summary>Video game equivalent of <see cref="WriteTvShowLinkAsync"/>.</summary>
    private async Task WriteVideoGameLinkAsync(VideoGameReferenceModel reference, ReferenceLinkTarget target)
    {
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceLinkAsync(target, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);
    }

    /// <summary>
    /// Re-fetches a video game reference from the deployment's default provider, always in full, since neither IGDB nor RAWG has TMDB's per-id "has this changed" endpoint.
    /// See <see cref="RefreshTvShowReferenceAsync"/> for the staleness cutoff this runs under.
    /// A reference without the default provider's id gets one adopted first (<see cref="TryAdoptDefaultVideoGameProviderAsync"/>).
    /// <para>
    /// <b>Only the default provider is called</b>, unlike <see cref="RefreshBookReferenceAsync"/>, which refreshes through whichever provider linked it.
    /// That suits books, where every registered provider is reachable.
    /// Video games have a second provider because the first went down, so falling back would make every unadopted reference pay a retry-and-timeout cycle against a dead host on every pass.
    /// An operator who selects a provider should not see traffic to another one.
    /// </para>
    /// <para>
    /// A reference that can't be adopted keeps the data it has and is stamped as checked.
    /// <c>FindStaleAsync</c> serves the least recently enriched first under a per-pass cap, so a document whose <see cref="VideoGameReferenceModel.LastEnrichedAt"/> never moves would sit at the head of the queue and starve everything behind it.
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
        // Stamped rather than returned bare: re-asking next pass won't change a provider having nothing for an id it issued.
        // This pass may also have adopted that id or recorded an attempt, which returning without a write would throw away, to be paid again every pass.
        if (details is null) return (await StampCheckedAsync(reference), false);

        reference.Title = details.Title;
        reference.Year = details.Year ?? reference.Year;
        reference.Synopsis = details.Synopsis;
        reference.Platforms = details.Platforms;
        reference.Genres = details.Genres;
        reference.Ratings = MergeProviderRatings(reference.Ratings, details.Ratings, client.SupportedRatingSources);
        reference.ImageUrl = PreferredImageUrl(client.ProviderKey, reference.ExternalIds, reference.ImageUrl, details.ImageUrl);
        reference.MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await videoGameReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    /// <summary>
    /// Gives a reference that predates the current default provider one of that provider's ids, so it can be refreshed and rated through it.
    /// <para>
    /// This carries a catalogue across a provider change without a migration script.
    /// Otherwise a reference linked through the old provider keeps only its ratings, and shows nothing once an admin selects a rating source only the new provider reports.
    /// It rides the sync's per-document loop, costing one search per unadopted reference per pass, and nothing once adopted.
    /// </para>
    /// <para>
    /// It requires exactly one candidate whose title matches the reference's, with a compatible year.
    /// A reference's title and year are canonical provider data rather than tenant text, so such a match is a genuine confirmation.
    /// Two games sharing a title is ordinary in this domain, so anything ambiguous is left for an admin to link by hand.
    /// </para>
    /// </summary>
    private async Task TryAdoptDefaultVideoGameProviderAsync(VideoGameReferenceModel reference, IVideoGameReferenceClient client, CancellationToken cancellationToken)
    {
        if (reference.ExternalIds.ContainsKey(client.ProviderKey) || string.IsNullOrWhiteSpace(reference.Title)) return;

        // A title with no unambiguous match won't match on the next pass either, so re-asking every pass is waste (see VideoGameReferenceModel.ProviderAdoptionCheckedAt).
        // The admin reconciliation action ignores this window, so a stuck reference never waits only on the timer.
        if (reference.ProviderAdoptionCheckedAt.TryGetValue(client.ProviderKey, out var lastAttempt)
            && DateTime.UtcNow - lastAttempt < ProviderAdoptionReattemptAfter)
        {
            return;
        }

        var (candidates, matches) = await FindAdoptionCandidatesAsync(reference, reference.Title, client, cancellationToken);
        reference.ProviderAdoptionCheckedAt[client.ProviderKey] = DateTime.UtcNow;

        if (matches.Count != 1)
        {
            // Logged, since this is why a reference stays on the old provider, and "why is nothing adopting?" is invisible otherwise.
            // The candidate titles explain it: an ambiguous count usually means editions or DLC sharing a title, and zero usually means the providers disagree about the year.
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
    /// The candidates a provider offers for a reference's own canonical title, and the subset that confirms as the same game.
    /// Shared by background adoption and the admin reconciliation queue, so what the queue shows as "this would link" follows the rule that links unattended.
    /// <para>
    /// A ladder of queries, widening until one produces a <b>match</b>, the same shape as <see cref="BookReferenceClientBase"/>'s search policy.
    /// The exact-name lookup goes first, since it answers adoption's question completely (see <see cref="IVideoGameReferenceClient.FindGamesByExactTitleAsync"/>).
    /// The relevance search is the fallback for when the two catalogues spell the work differently.
    /// </para>
    /// <para>
    /// It widens when nothing <i>matched</i>, not when nothing came back, since a relevance search answers too easily.
    /// IGDB answers <c>NieR:Automata</c> with a single unrelated "Untitled NieR:Automata Project" and <c>Marvel Avengers</c> with three LEGO expansion packs, and stopping there never asks the rung that finds the game.
    /// Candidates accumulate across rungs, so an admin sees everything asked for rather than whatever the final query said.
    /// </para>
    /// <para>
    /// The rungs, in order (see <see cref="AdoptionQueryForms"/> and <see cref="TruncatedQueryForms"/>):
    /// the title as stored, then without a parenthesised disambiguator, then the punctuation-folded form.
    /// <c>GoldenEye 007 (1997)</c> makes IGDB return nothing at all, which no loose comparison can fix, having no candidate to compare.
    /// The folded form rescues a title whose punctuation the provider's search cannot parse.
    /// Last, and only while nothing has matched, the folded form with trailing words dropped: IGDB answers nothing to <c>NieR Replicant v1.22474487139</c> but finds the game for <c>NieR Replicant</c>.
    /// That candidate does not confirm, the catalogues spelling it differently, but putting it in front of an admin is the point of the reconciliation queue.
    /// </para>
    /// <para>
    /// Confirmation is <see cref="TitleNormalizer.NormalizeLoose"/> against the <b>reference's</b> own title plus a compatible year, never against the query that found the candidate.
    /// That keeps a widened or admin-typed query from confirming what the strict rule would refuse.
    /// Exact normalized equality would reject <c>Mass Effect: Legendary Edition</c> against IGDB's <c>Mass Effect Legendary Edition</c>, and every RAWG title with a <c>(1997)</c> suffix.
    /// Loose comparison is safe here because nothing else loosens: the reference's title and year are canonical provider data, the year must still agree, and anything but a single match is left for a human.
    /// </para>
    /// </summary>
    /// <param name="searchTitle">
    /// What to ask the provider: the reference's own title on the automatic path, or an admin's text from the reconciliation screen when the provider spells the work differently.
    /// IGDB's search never returns "Marvel's Avengers" for any spelling of it, and only an exact-name lookup finds it.
    /// Confirmation is unaffected, always against the reference.
    /// </param>
    /// <param name="reference"></param>
    /// <param name="client"></param>
    /// <param name="cancellationToken"></param>
    private static async Task<(IReadOnlyList<VideoGameSearchResult> Candidates, IReadOnlyList<VideoGameSearchResult> Matches)> FindAdoptionCandidatesAsync(
        VideoGameReferenceModel reference, string searchTitle, IVideoGameReferenceClient client, CancellationToken cancellationToken)
    {
        var candidates = new List<VideoGameSearchResult>();
        IReadOnlyList<VideoGameSearchResult> matches = [];

        // Re-confirms over everything seen so far, so a match found by a looser rung is judged by the same rule as the first.
        // Search ranking and automatic resolution read the same ReferenceMatchRules.
        bool Accumulate(IReadOnlyList<VideoGameSearchResult> found)
        {
            candidates.AddRange(found.Where(result => candidates.TrueForAll(known => known.ExternalId != result.ExternalId)));
            matches = ReferenceMatchRules.ConfirmedMatches(candidates, reference.Title, reference.Year);
            return matches.Count > 0;
        }

        var forms = AdoptionQueryForms(searchTitle);

        foreach (var query in forms)
        {
            if (Accumulate(await client.FindGamesByExactTitleAsync(query, cancellationToken))) return (candidates, matches);
        }

        foreach (var query in forms)
        {
            if (Accumulate(await client.SearchGamesAsync(query, reference.Year, cancellationToken))) return (candidates, matches);
        }

        foreach (var query in TruncatedQueryForms(searchTitle).Where(query => !forms.Contains(query, StringComparer.Ordinal)))
        {
            var found = await client.SearchGamesAsync(query, reference.Year, cancellationToken);
            // each shorter query is vaguer than the one before, so the first that answers at all is the most specific this rung gets
            if (Accumulate(found) || found.Count > 0) return (candidates, matches);
        }

        // Last resort, and the only shape that survives the provider punctuating a title differently: every word as a substring, in any order.
        // It is unranked, so the answer is shortlisted rather than shown whole (see ShortlistByClosestTitle).
        var words = TitleNormalizer.ToProviderQuery(searchTitle).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length >= MinTruncatedQueryWords)
        {
            Accumulate(ShortlistByClosestTitle(await client.FindGamesContainingAllWordsAsync(words, cancellationToken), reference));
        }

        return (candidates, matches);
    }

    /// <summary>
    /// The <see cref="MaxShortlistedCandidates"/> best answers for this reference out of an unranked query: <see cref="ReferenceMatchRules.OrderByBestMatch"/> cut to length.
    /// <para>
    /// A substring filter returns everything containing the words, with no opinion about which is the game.
    /// "marvel" plus "avengers" returns 40 entries, mostly editions, DLC and crossovers.
    /// Sorting by title distance puts the plain work first ("Marvel's Avengers" leads those 40) and every longer variant behind it.
    /// </para>
    /// <para>
    /// The cap is safe because the ordering leads with candidates that loosely equal the title, so the shortlist never cuts a genuine match.
    /// </para>
    /// </summary>
    private static IReadOnlyList<VideoGameSearchResult> ShortlistByClosestTitle(IReadOnlyList<VideoGameSearchResult> found, VideoGameReferenceModel reference) =>
        ReferenceMatchRules.OrderByBestMatch(found, reference.Title, reference.Year).Take(MaxShortlistedCandidates).ToList();

    /// <summary>
    /// How many of an unranked substring query's results reach the admin's row.
    /// Enough for the work plus its nearest namesakes, few enough that the row stays a short list.
    /// </summary>
    private const int MaxShortlistedCandidates = 8;

    /// <summary>
    /// The full-title queries a provider is asked, in order and without repeats: the title as stored, without a parenthesised disambiguator, and punctuation-folded (<see cref="TitleNormalizer.ToProviderQuery"/>).
    /// At most three, and a single one for the common title with no punctuation.
    /// </summary>
    private static List<string> AdoptionQueryForms(string title) =>
        new List<string> { title, TitleNormalizer.StripDisambiguator(title), TitleNormalizer.ToProviderQuery(title) }
            .Where(form => form.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// The last-resort queries: the folded title with trailing words dropped, longest first.
    /// Bounded by <see cref="MaxTruncatedQueries"/> and never shorter than <see cref="MinTruncatedQueryWords"/> words, so a stuck reference costs a few extra calls once per <see cref="ProviderAdoptionReattemptAfter"/>, not one per word.
    /// <para>
    /// Both bounds were measured against the real IGDB API on stuck rows.
    /// Dropping one word turns "Pokemon Lets Go Pikachu and Eevee" into an answer, and dropping two does it for "NieR Replicant v1 22474487139".
    /// The two-word floor stops a search for a bare "Marvel" or "Final", which returns a page of unrelated games no confirmation would accept.
    /// </para>
    /// </summary>
    private static IEnumerable<string> TruncatedQueryForms(string title)
    {
        var words = TitleNormalizer.ToProviderQuery(title).Split(' ', StringSplitOptions.RemoveEmptyEntries);

        for (var length = words.Length - 1; length >= MinTruncatedQueryWords && length > words.Length - 1 - MaxTruncatedQueries; length--)
        {
            yield return string.Join(' ', words.Take(length));
        }
    }

    /// <summary>How many trailing-word-dropped queries a single reference may cost, at most.</summary>
    private const int MaxTruncatedQueries = 3;

    /// <summary>The shortest query worth asking (see <see cref="TruncatedQueryForms"/>).</summary>
    private const int MinTruncatedQueryWords = 2;

    /// <summary>
    /// The admin reconciliation queue: every video game reference with no id from the current default provider, ordered by title.
    /// <para>
    /// This is exactly the set of works Explore cannot tell the owner already has.
    /// Explore excludes a suggestion by the discovery provider's id, so a reference holding only the previous provider's id is invisible to it.
    /// The title fallback misses the same documents for the same reason adoption did: the two catalogues spell the work differently.
    /// Draining this queue makes discovery correct.
    /// </para>
    /// </summary>
    public async Task<(string Provider, string DisplayName, int Total, IReadOnlyList<VideoGameReferenceModel> Missing)> FindVideoGameProviderGapsAsync()
    {
        var client = videoGameReferenceClientRegistry.Resolve(null);
        var missing = await videoGameReferenceRepository.FindWithoutExternalIdAsync(client.ProviderKey);
        var total = (await videoGameReferenceRepository.FindAllAsync()).Count;
        return (client.ProviderKey, client.DisplayName, total, missing);
    }

    /// <summary>
    /// What the default provider offers for one reference, flagging the subset the automatic path would accept.
    /// It is the per-row detail of the queue above, fetched on demand, since each row costs a provider call or two.
    /// <para>
    /// It ignores <see cref="ProviderAdoptionReattemptAfter"/>, since an admin looking at the row is waiting on the answer, as the interactive rating paths ignore their own window.
    /// </para>
    /// </summary>
    /// <param name="query">
    /// Optional text the admin typed instead of the reference's stored title, for rows no automatic query reaches.
    /// IGDB's relevance search answers "Marvel's Avengers" with three LEGO expansion packs however it is spelled, and only an exact-name lookup for the provider's own string finds the game.
    /// <para>
    /// A pasted provider page URL or a bare numeric id is resolved directly instead of searched (<see cref="IVideoGameReferenceClient.FindGameByIdentifierAsync"/>).
    /// It is the escape hatch for a game no query finds, since a human can always copy the address from the provider's site.
    /// </para>
    /// </param>
    /// <param name="referenceId"></param>
    /// <param name="cancellationToken"></param>
    public async Task<(IReadOnlyList<VideoGameSearchResult> Candidates, IReadOnlyList<string> MatchingIds)> FindVideoGameAdoptionCandidatesAsync(
        string referenceId, string? query = null, CancellationToken cancellationToken = default)
    {
        var reference = await videoGameReferenceRepository.FindByIdAsync(referenceId)
                        ?? throw new ArgumentException($"No video game reference with id '{referenceId}'.", nameof(referenceId));

        var client = videoGameReferenceClientRegistry.Resolve(null);
        var searchTitle = string.IsNullOrWhiteSpace(query) ? reference.Title : query.Trim();

        if (ProviderWebLinks.TryReadIdentifier(searchTitle, out var identifier))
        {
            var game = await client.FindGameByIdentifierAsync(identifier, cancellationToken);
            // An id names exactly one game, yet it is reported as a candidate rather than adopted outright.
            // The admin picked the page, and the Link button is where that choice is confirmed.
            return (game is null ? [] : [game], []);
        }

        var (candidates, matches) = await FindAdoptionCandidatesAsync(reference, searchTitle, client, cancellationToken);
        // Best answer first rather than whichever rung replied first, since a provider's search readily returns unrelated titles.
        // An ordinary search uses the same ordering, so the two screens never disagree about the best candidate.
        return (ReferenceMatchRules.OrderByBestMatch(candidates, reference.Title, reference.Year).ToList(), matches.Select(m => m.ExternalId).ToList());
    }

    /// <summary>
    /// Attaches a provider id an admin picked to an existing reference document, then refreshes it through that provider.
    /// It is the manual half of adoption, for references the automatic rule refuses: several games sharing one name, or two catalogues disagreeing about the year.
    /// <para>
    /// It writes the id onto the <b>existing</b> document and reuses <see cref="RefreshVideoGameReferenceAsync"/>, never <see cref="ResolveVideoGameAsync"/>.
    /// Resolution matches on text and could mint a second document for a work that already has one, the very failure this action cleans up.
    /// </para>
    /// </summary>
    public async Task<VideoGameReferenceModel> AdoptVideoGameProviderIdAsync(string referenceId, string externalId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalId);

        var reference = await videoGameReferenceRepository.FindByIdAsync(referenceId)
                        ?? throw new ArgumentException($"No video game reference with id '{referenceId}'.", nameof(referenceId));
        var client = videoGameReferenceClientRegistry.Resolve(null);

        var claimant = await videoGameReferenceRepository.FindByExternalIdAsync(client.ProviderKey, externalId);
        if (claimant is not null && claimant.Id != reference.Id)
        {
            // The unique partial index would reject this write anyway, but failing here names the document already holding the id.
            // That turns "it didn't work" into "merge these two".
            throw new ArgumentException(
                $"{client.DisplayName} id '{externalId}' already belongs to the reference \"{claimant.Title}\" ({claimant.Year}). Merge the two references instead.",
                nameof(externalId));
        }

        reference.ExternalIds[client.ProviderKey] = externalId;
        reference.ProviderAdoptionCheckedAt[client.ProviderKey] = DateTime.UtcNow;
        logger.LogInformation(
            "Admin adopted {Provider} id {ExternalId} for video game reference {ReferenceId} \"{Title}\".",
            client.ProviderKey, externalId, reference.Id, reference.Title);

        var (saved, _) = await RefreshVideoGameReferenceAsync(reference, cancellationToken);
        return saved;
    }

    /// <summary>
    /// Every set of separate video game references that look like the same work under <see cref="TitleNormalizer.NormalizeLoose"/>.
    /// A provider change leaves them behind, and a reference-data import creates them: it matches by provider id, so IGDB-linked games land beside RAWG-linked copies.
    /// <para>
    /// A duplicate is not cosmetic.
    /// Tenants' items point at whichever document existed when they linked, so a work's ratings, cover and provider ids are split across two records, and Explore excludes on only one.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<IReadOnlyList<VideoGameReferenceModel>>> FindDuplicateVideoGameReferencesAsync()
    {
        var references = await videoGameReferenceRepository.FindAllAsync();
        return references
            .GroupBy(r => TitleNormalizer.NormalizeLoose(r.Title))
            .Where(group => group.Count() > 1)
            // a same-name pair from different years (a remake) is two works, not a duplicate, the year rule adoption confirms with
            .Where(group => group.Select(r => r.Year).Distinct().Count() == 1)
            .Select(IReadOnlyList<VideoGameReferenceModel> (group) => group.OrderBy(r => r.Id, StringComparer.Ordinal).ToList())
            .ToList();
    }

    /// <summary>
    /// Folds one duplicate reference document into another.
    /// The survivor gains what the other knew and it didn't, every tenant item pointing at the absorbed one is re-pointed, and the absorbed document is deleted.
    /// <para>
    /// It fills the gaps in <paramref name="keepId"/> and never overwrites, like <c>SetReferenceLinkAsync</c> and the reference-data import.
    /// Where both hold a value for the same provider id or rating source, that provider wrote both about the same work, so either is right.
    /// A field only one of them has is new information.
    /// </para>
    /// <para>
    /// Every hydrated cover, rating and Explore exclusion goes through a tenant's <c>ReferenceId</c>.
    /// Deleting the absorbed document without re-pointing its items would silently blank all three.
    /// </para>
    /// </summary>
    public async Task<(VideoGameReferenceModel Kept, long ItemsRepointed)> MergeVideoGameReferencesAsync(string keepId, string mergeId)
    {
        if (keepId == mergeId) throw new ArgumentException("A reference cannot be merged into itself.", nameof(mergeId));

        var keep = await videoGameReferenceRepository.FindByIdAsync(keepId)
                   ?? throw new ArgumentException($"No video game reference with id '{keepId}'.", nameof(keepId));
        var absorbed = await videoGameReferenceRepository.FindByIdAsync(mergeId)
                       ?? throw new ArgumentException($"No video game reference with id '{mergeId}'.", nameof(mergeId));

        // Computed before the ids are unioned: "is this a RAWG image" is "does this document carry a rawg id", true of each document only while they are separate.
        // After the union the survivor carries a rawg id whatever its cover, so its IGDB box art would pass the test and the real key art would be dropped.
        var mergedImageUrl = MergedImageUrl(keep, absorbed);

        foreach (var (provider, externalId) in absorbed.ExternalIds)
        {
            keep.ExternalIds.TryAdd(provider, externalId);
        }

        foreach (var (source, rating) in absorbed.Ratings)
        {
            keep.Ratings.TryAdd(source, rating);
        }

        foreach (var (provider, checkedAt) in absorbed.ProviderAdoptionCheckedAt)
        {
            // the later attempt wins, so a merge can never move a re-attempt window backwards
            if (!keep.ProviderAdoptionCheckedAt.TryGetValue(provider, out var existing) || existing < checkedAt)
            {
                keep.ProviderAdoptionCheckedAt[provider] = checkedAt;
            }
        }

        keep.MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(keep.MatchedAliases, [.. absorbed.MatchedAliases.Select(a => (a.Title, a.Year, a.Creator, a.Isbn))]);
        keep.Year ??= absorbed.Year;
        keep.Synopsis ??= absorbed.Synopsis;
        keep.ImageUrl = mergedImageUrl;
        if (keep.Platforms.Count == 0) keep.Platforms = absorbed.Platforms;
        if (keep.Genres.Count == 0) keep.Genres = absorbed.Genres;

        // The absorbed document goes first, since while both exist they hold the same provider ids, and the unique partial indexes on external_ids.* reject the second writer.
        await videoGameReferenceRepository.DeleteAsync(mergeId);
        var saved = await videoGameReferenceRepository.UpsertAsync(keep);

        var repointed = await videoGameRepository.RepointReferenceAsync(mergeId, saved.Id!);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);

        logger.LogInformation(
            "Merged video game reference {MergedId} into {KeptId} (\"{Title}\"); {ItemCount} tenant item(s) re-pointed.",
            mergeId, saved.Id, saved.Title, repointed);
        return (saved, repointed);
    }

    /// <summary>
    /// Which cover the merged document keeps: <b>a RAWG-linked document's image wins</b>, then the survivor's own, then the absorbed one's.
    /// <para>
    /// It is <see cref="PreferredImageUrl"/>'s rule, for the same reason: RAWG's key art outranks IGDB's box art and cannot be fetched again (see there).
    /// A typical duplicate pair is one RAWG-linked document and one IGDB-linked one, so "keep the survivor's" would drop the key art whenever the admin kept the IGDB document.
    /// </para>
    /// <para>
    /// Here the id test is exact rather than a proxy: each document is still separate and was written by one provider, so "carries a rawg id" means "this image came from RAWG".
    /// That holds only before the ids are unioned (see the caller).
    /// </para>
    /// </summary>
    private static string? MergedImageUrl(VideoGameReferenceModel keep, VideoGameReferenceModel absorbed) =>
        RawgImageOf(keep) ?? RawgImageOf(absorbed) ?? keep.ImageUrl ?? absorbed.ImageUrl;

    private static string? RawgImageOf(VideoGameReferenceModel reference) =>
        reference.ExternalIds.ContainsKey(RatingSourceCatalog.Rawg) && !string.IsNullOrEmpty(reference.ImageUrl)
            ? reference.ImageUrl
            : null;

    /// <summary>
    /// The image a video game reference keeps: whatever <paramref name="providerKey"/> just returned, except that a provider other than RAWG may not overwrite a stored image on a reference carrying a RAWG id.
    /// <para>
    /// RAWG's <c>background_image</c> is curated landscape key art, and its CDN still serves those URLs though its API does not.
    /// IGDB has no equivalent: its cover is portrait box art, its artwork is contributed and unreliable, and its screenshots are raw frames with HUD.
    /// Replacing a working RAWG image with any of those is a downgrade.
    /// </para>
    /// <para>
    /// It is also irreversible, since a RAWG URL cannot be rebuilt from the RAWG id without RAWG's API.
    /// A small cosmetic gain against permanent data loss makes keeping the stored image the default.
    /// </para>
    /// <para>
    /// <b>RAWG itself is exempt.</b>
    /// "Carries a RAWG id" is only a proxy for "the stored image is a RAWG image", and the two diverge once a document holds both ids, the normal state after <see cref="TryAdoptDefaultVideoGameProviderAsync"/>.
    /// Without the exemption, an admin re-linking through RAWG (<see cref="ReferenceDataAdminController"/> passes the picked provider to <see cref="ResolveVideoGameAsync"/>) would have the fresh key art discarded for the stored IGDB cover.
    /// A dead RAWG URL would also be repairable only by unlinking, which deletes the shared reference document.
    /// </para>
    /// </summary>
    private static string? PreferredImageUrl(string providerKey, Dictionary<string, string> externalIds, string? existingImageUrl, string? fetchedImageUrl) =>
        providerKey != RatingSourceCatalog.Rawg
        && externalIds.ContainsKey(RatingSourceCatalog.Rawg)
        && !string.IsNullOrEmpty(existingImageUrl)
            ? existingImageUrl
            : fetchedImageUrl ?? existingImageUrl;

    /// <summary>
    /// Records that a pass looked at a reference without fetching anything, so the staleness queue rotates past it (see <see cref="RefreshVideoGameReferenceAsync"/>).
    /// </summary>
    private async Task<VideoGameReferenceModel> StampCheckedAsync(VideoGameReferenceModel reference)
    {
        reference.LastEnrichedAt = DateTime.UtcNow;
        return await videoGameReferenceRepository.UpsertAsync(reference);
    }
}
