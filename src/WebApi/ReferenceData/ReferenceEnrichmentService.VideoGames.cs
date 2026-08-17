using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// How long a fruitless provider-id adoption attempt is remembered before it is worth asking again.
    /// Shorter than the rating re-attempt window because the answer can change for an ordinary reason (the
    /// provider corrects a year, or adds the missing entry), and long enough that the references a provider
    /// genuinely can't match stop costing two calls a day each.
    /// </summary>
    private static readonly TimeSpan ProviderAdoptionReattemptAfter = TimeSpan.FromDays(7);

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

        // No title-only fallback here, unlike the other four domains: a year is required for any automatic
        // link in this domain (see TryAutoResolveVideoGameAsync). The fallback exists for a tenant who
        // recorded no year at all, and for video games that tenant is exactly the one who must not be linked
        // to a title's first namesake.
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
    /// What the detail page's "check for reference match" does for video games: reuse a fact someone already
    /// established, and only when there is none, ask the provider under the same confirmed-single-match rule
    /// automatic resolution uses.
    /// <para>
    /// The escalation exists because the local-only half cannot keep the promise the button makes - the
    /// control's own tooltip reads <i>"Not right? Edit the title or year below, then check again."</i> An item
    /// created before its year was known writes <b>no</b> reference at all (resolution runs on create, and
    /// correctly refuses to choose between same-titled games without a year), so from then on there is nothing
    /// local for any amount of correcting the title and year to find, and the button silently does nothing
    /// forever. Confirmed in the running app on "Code Vein: Season Pass".
    /// </para>
    /// <para>
    /// It adds no new guessing: it links exactly what <see cref="TryAutoResolveVideoGameAsync"/> would have
    /// linked on create, so a title with namesakes and no year still resolves to nothing. What it adds is a
    /// second chance to run that rule once the tenant has supplied what it needs, which is otherwise only
    /// available by creating the item again.
    /// </para>
    /// <para>
    /// <b>Video games only, deliberately.</b> This domain's rule is the strict one (named the work, agreeing
    /// about the year); the other four still resolve on "the provider returned exactly one result", and
    /// escalating on that would turn a local-only control into a provider call that can link something nobody
    /// compared. It also keeps a user-triggered provider call out of four domains that work as they are.
    /// </para>
    /// </summary>
    public async Task<VideoGameModel> LinkVideoGameReferenceAsync(VideoGameModel model)
    {
        model = await TryLinkExistingVideoGameReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        // resolution propagates by title+year across every tenant's matching item rather than returning this
        // one, so the caller's copy is re-read rather than patched up here
        await TryAutoResolveVideoGameAsync(model.Title, model.Year);
        return await videoGameRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
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
    /// <para>
    /// What counts as confident is <see cref="ReferenceMatchRules.ConfirmedMatches"/>: a single candidate that
    /// is actually named this game and agrees about the year. It deliberately is <b>not</b> "the provider
    /// returned exactly one result", which is what this used to be and which reads a property of the *search*
    /// as a property of the *answer*. That was wrong in both directions. It linked whatever came back whenever
    /// a query happened to be narrow - IGDB answers "NieR:Automata" with a single "Untitled NieR:Automata
    /// Project", which it would have linked without ever comparing the two titles. And it refused every title
    /// with namesakes however unambiguous the year made it: IGDB holds eight games named exactly "Resident Evil
    /// 2", so a tenant recording the 2019 remake could never resolve automatically, though only one of the
    /// eight is from 2019.
    /// </para>
    /// <para>
    /// Strictly fewer wrong links, and a title the provider spells differently now lands in the admin queue
    /// instead of linking to whatever the search returned - the same "a queue entry is one click, a wrong link
    /// is silent data loss" trade every other rule in this file makes.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveVideoGameAsync(string title, int? year)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync

        // A year is required for any automatic link in this domain (owner's rule). Video game catalogues are
        // full of same-titled works - IGDB holds eight games named exactly "Resident Evil 2" - so a title on
        // its own identifies nothing, and the cases where it happens to identify exactly one game are not
        // worth a rule that silently links the wrong thing everywhere else. Supplying a year is a legitimate
        // part of the contract for an immediate match; without one the item waits, and the detail page's
        // "check for reference match" resolves it the moment a year is filled in.
        if (year is null) return;

        // a reference someone already confirmed for this exact (title, year) is the answer - see TryLinkKnownReferenceAsync for why it is worth asking before the provider is
        if (await TryLinkKnownReferenceAsync(
                () => videoGameReferenceRepository.FindByTitleYearAsync(title, year),
                reference => PropagateVideoGameLinkAsync(reference, title, year)))
        {
            return;
        }

        var client = videoGameReferenceClientRegistry.Resolve(null);
        var candidates = await client.SearchGamesAsync(title, year);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveVideoGameAsync(title, year, matches[0].ExternalId, client.ProviderKey);
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
            MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Genres = details.Genres,
            Ratings = MergeProviderRatings(existing?.Ratings, details.Ratings, client.SupportedRatingSources),
            ImageUrl = PreferredImageUrl(client.ProviderKey, externalIds, existing?.ImageUrl, details.ImageUrl),
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await videoGameReferenceRepository.UpsertAsync(model);
        await PropagateVideoGameLinkAsync(saved, title, year);
        return saved;
    }

    /// <summary>Video game equivalent of <see cref="PropagateTvShowLinkAsync"/>.</summary>
    private async Task PropagateVideoGameLinkAsync(VideoGameReferenceModel reference, string searchTitle, int? searchYear)
    {
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.VideoGame));
        await videoGameRepository.SetReferenceLinkAsync(searchTitle, searchYear, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);
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
        // stamped rather than returned bare: the provider had nothing for an id it issued, which no amount of
        // re-asking next pass changes - and this pass may just have adopted that id (or recorded an adoption
        // attempt), which returning without a write would silently throw away and re-pay for every pass.
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

        // a title this provider has no unambiguous match for cannot be searched into working, so re-asking on
        // every pass is pure waste - see VideoGameReferenceModel.ProviderAdoptionCheckedAt. The admin
        // reconciliation action ignores this window, so a stuck reference is never *only* the timer's problem.
        if (reference.ProviderAdoptionCheckedAt.TryGetValue(client.ProviderKey, out var lastAttempt)
            && DateTime.UtcNow - lastAttempt < ProviderAdoptionReattemptAfter)
        {
            return;
        }

        var (candidates, matches) = await FindAdoptionCandidatesAsync(reference, reference.Title, client, cancellationToken);
        reference.ProviderAdoptionCheckedAt[client.ProviderKey] = DateTime.UtcNow;

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
    /// The candidates a provider offers for a reference's own canonical title, and the subset that confirms as
    /// the same game. Shared by the background adoption above and the admin reconciliation queue, so what the
    /// queue shows as "this would link" is decided by the same rule that decides whether to link it
    /// unattended.
    /// <para>
    /// A ladder of queries, widening until one of them produces a <b>match</b> - the same "never let a
    /// narrower query return worse than a broader one" shape as <see cref="BookReferenceClientBase"/>'s search
    /// policy. The exact-name lookup goes first because it answers adoption's actual question completely (see
    /// <see cref="IVideoGameReferenceClient.FindGamesByExactTitleAsync"/>); the relevance search is the
    /// fallback for when the two catalogues spell the work differently.
    /// </para>
    /// <para>
    /// It widens on "nothing <i>matched</i>", not on "nothing came back", and that is the whole difference
    /// between a stuck reference and an adopted one. An earlier version stopped at the first non-empty
    /// answer, which a provider's relevance search hands out far too easily: confirmed live, IGDB answers
    /// <c>NieR:Automata</c> with a single unrelated "Untitled NieR:Automata Project" and <c>Marvel Avengers</c>
    /// with three LEGO expansion packs, and each of those ended the ladder on the spot - so the rung that
    /// would have found the game was never asked. Candidates accumulate across every rung instead of the last
    /// one replacing the ones before it, so an admin sees everything that was asked for rather than whatever
    /// the final query happened to say.
    /// </para>
    /// <para>
    /// The rungs, in order (see <see cref="AdoptionQueryForms"/> and <see cref="TruncatedQueryForms"/>): the
    /// title as stored, the same without a parenthesised disambiguator - because a title like
    /// <c>GoldenEye 007 (1997)</c> makes IGDB return nothing whatsoever, a case no amount of loose
    /// *comparison* can fix since there are no candidates to compare against - and then the punctuation-folded
    /// form, which is what rescues a title whose punctuation the provider's search cannot parse. Last and only
    /// while nothing has matched, the folded form with trailing words dropped: a provider that answers nothing
    /// at all to <c>NieR Replicant v1.22474487139</c> answers <c>NieR Replicant</c> with the very game, and
    /// while that candidate does not *confirm* (the two catalogues genuinely spell it differently), putting it
    /// in front of an admin is the entire point of the reconciliation queue.
    /// </para>
    /// <para>
    /// Confirmation is <see cref="TitleNormalizer.NormalizeLoose"/> against the <b>reference's</b> own title
    /// plus a compatible year - never against whatever query found the candidate, which is what keeps a
    /// widened or admin-typed query from confirming something the strict rule would have refused. It is not
    /// exact normalized equality: that is what left a third of a real catalogue unable to adopt, rejecting
    /// <c>Mass Effect: Legendary Edition</c> against IGDB's <c>Mass Effect Legendary Edition</c> and every RAWG
    /// title carrying a <c>(1997)</c> disambiguation suffix. Loosening the *shortlist* is safe because nothing
    /// else loosens: a reference's title and year are canonical provider data rather than tenant-typed text,
    /// the year must still agree, and anything but a single match is still left for a human.
    /// </para>
    /// </summary>
    /// <param name="searchTitle">
    /// What to ask the provider about - the reference's own title for the automatic path, or an admin's typed
    /// text from the reconciliation screen when the provider simply does not spell the work the way this
    /// document does (IGDB's search never returns "Marvel's Avengers" for any spelling of it, whatever the
    /// query; only an exact-name lookup finds it). Confirmation is unaffected: it is always the reference that
    /// a candidate has to match.
    /// </param>
    /// <param name="reference"></param>
    /// <param name="client"></param>
    /// <param name="cancellationToken"></param>
    private static async Task<(IReadOnlyList<VideoGameSearchResult> Candidates, IReadOnlyList<VideoGameSearchResult> Matches)> FindAdoptionCandidatesAsync(
        VideoGameReferenceModel reference, string searchTitle, IVideoGameReferenceClient client, CancellationToken cancellationToken)
    {
        var candidates = new List<VideoGameSearchResult>();
        IReadOnlyList<VideoGameSearchResult> matches = [];

        // accumulates one rung's answer and re-confirms over everything seen so far, so a match found by a
        // later, looser query is still judged against the same strict rule as the first rung's - and the same
        // rule a search ranks by and automatic resolution links on, since all three read ReferenceMatchRules
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
            // a shorter query is strictly vaguer than the one before it, so the first that answers at all is
            // the most specific answer this rung will ever get - going further only buys noise
            if (Accumulate(found) || found.Count > 0) return (candidates, matches);
        }

        // last resort, and the only shape that survives the provider spelling a title with punctuation this
        // reference doesn't: every word as a substring, in any order. It is unranked by construction, so what
        // comes back is shortlisted here rather than shown whole - see ShortlistByClosestTitle.
        var words = TitleNormalizer.ToProviderQuery(searchTitle).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length >= MinTruncatedQueryWords)
        {
            Accumulate(ShortlistByClosestTitle(await client.FindGamesContainingAllWordsAsync(words, cancellationToken), reference));
        }

        return (candidates, matches);
    }

    /// <summary>
    /// The <see cref="MaxShortlistedCandidates"/> best answers for this reference, out of everything an
    /// unranked query returned - <see cref="ReferenceMatchRules.OrderByBestMatch"/> cut to length.
    /// <para>
    /// A substring filter answers with everything that contains the words and no opinion about which is the
    /// game - "marvel" + "avengers" returns 40 entries on the real catalogue, mostly editions, DLC and
    /// crossovers - so an opinion has to be supplied here. Sorting by how far a candidate's title is from the
    /// one being looked for puts the plain work first (measured: "Marvel's Avengers" leads those 40) and every
    /// longer variant behind it.
    /// </para>
    /// <para>
    /// The cap is safe because the ordering leads with candidates that loosely equal the title, so a genuine
    /// match can never be cut off by the shortlist.
    /// </para>
    /// </summary>
    private static IReadOnlyList<VideoGameSearchResult> ShortlistByClosestTitle(IReadOnlyList<VideoGameSearchResult> found, VideoGameReferenceModel reference) =>
        ReferenceMatchRules.OrderByBestMatch(found, reference.Title, reference.Year).Take(MaxShortlistedCandidates).ToList();

    /// <summary>
    /// How many of an unranked substring query's results reach the admin's row. Enough to hold the work plus
    /// its nearest namesakes, few enough that the row stays a list of candidates rather than a page of them.
    /// </summary>
    private const int MaxShortlistedCandidates = 8;

    /// <summary>
    /// The full-title queries a provider is asked, in order and without repeating one: the title as stored,
    /// the title without a parenthesised disambiguator, and the punctuation-folded form
    /// (<see cref="TitleNormalizer.ToProviderQuery"/>). At most three, and fewer for the ordinary title that
    /// carries no punctuation at all - which is the common case and costs exactly what it always did.
    /// </summary>
    private static List<string> AdoptionQueryForms(string title) =>
        new List<string> { title, TitleNormalizer.StripDisambiguator(title), TitleNormalizer.ToProviderQuery(title) }
            .Where(form => form.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// The last-resort queries: the folded title with trailing words dropped, longest first. Bounded by
    /// <see cref="MaxTruncatedQueries"/> and never shorter than <see cref="MinTruncatedQueryWords"/> words, so
    /// a stuck reference costs a handful of extra calls once per
    /// <see cref="ProviderAdoptionReattemptAfter"/> rather than one per word.
    /// <para>
    /// Both bounds were measured against the real IGDB API on this database's own stuck rows: dropping one
    /// word turns "Pokemon Lets Go Pikachu and Eevee" into an answer, dropping two turns
    /// "NieR Replicant v1 22474487139" into one, and a two-word floor is what stops a search for a bare
    /// "Marvel" or "Final" being asked at all - a query that broad returns a page of unrelated games no
    /// confirmation would ever accept.
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

    /// <summary>The shortest query worth asking - see <see cref="TruncatedQueryForms"/>.</summary>
    private const int MinTruncatedQueryWords = 2;

    /// <summary>
    /// The admin reconciliation queue: every video game reference that carries no id in the current default
    /// provider's number space, newest gap concerns first by title.
    /// <para>
    /// This set is not a curiosity - it is exactly the set of works the Explore feature cannot tell the owner
    /// already has. Explore excludes a suggestion by asking each linked reference for the *discovery*
    /// provider's id, so a reference still living in the previous provider's id space is invisible to it, and
    /// the title fallback misses the same documents for the same reason adoption did (the two catalogues spell
    /// the work differently). Draining this queue is what makes discovery correct again.
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
    /// What the default provider offers for one reference, with the subset the automatic path would have
    /// accepted flagged - the per-row detail of the queue above, fetched on demand rather than for every row at
    /// once, since each row costs a provider call or two.
    /// <para>
    /// Deliberately ignores <see cref="ProviderAdoptionReattemptAfter"/>: an admin looking at this row is
    /// waiting on the answer, the same reason the interactive rating paths ignore their own re-attempt window.
    /// </para>
    /// </summary>
    /// <param name="query">
    /// Optional: what the admin typed instead of the reference's stored title, for the rows no automatic query
    /// can reach. It is not a nicety - confirmed live, IGDB's relevance search answers "Marvel's Avengers"
    /// with three LEGO expansion packs whichever way the phrase is spelled, and only an exact-name lookup for
    /// the provider's own string finds the game. Typing that string here is the difference between a row an
    /// admin can clear and one that is stuck forever.
    /// <para>
    /// A pasted provider page URL (or a bare numeric id) is resolved directly instead of searched, via
    /// <see cref="IVideoGameReferenceClient.FindGameByIdentifierAsync"/> - the escape hatch for a game whose
    /// name no query finds at all, since a human can always open the provider's site and copy the address.
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
            // an id names exactly one game, so there is nothing to disambiguate - but it is still reported as
            // an ordinary candidate rather than adopted outright: the admin picked the page, and the Link
            // button is where that choice is confirmed.
            return (game is null ? [] : [game], []);
        }

        var (candidates, matches) = await FindAdoptionCandidatesAsync(reference, searchTitle, client, cancellationToken);
        // best answer first, so the row leads with the likeliest candidate rather than with whichever rung
        // replied first - a provider's search hands back unrelated titles readily enough that "the first card"
        // and "the game" were routinely not the same thing. Same ordering an ordinary search shows, so the two
        // screens can never disagree about which candidate looks best.
        return (ReferenceMatchRules.OrderByBestMatch(candidates, reference.Title, reference.Year).ToList(), matches.Select(m => m.ExternalId).ToList());
    }

    /// <summary>
    /// Attaches a provider id an admin picked to an existing reference document, then refreshes it through
    /// that provider - the manual half of adoption, for the references the automatic rule refuses (several
    /// games sharing one name, or two catalogues disagreeing about the year).
    /// <para>
    /// It writes the id onto the <b>existing</b> document and reuses
    /// <see cref="RefreshVideoGameReferenceAsync"/> rather than going through
    /// <see cref="ResolveVideoGameAsync"/>: resolving by title would find this same document in the ordinary
    /// case but is matched on text, and the one thing this action must never do is mint a *second* reference
    /// document for a work that already has one - that is the failure it exists to clean up.
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
            // the unique partial index would reject this write anyway; failing here says *which* document
            // already holds the id, which is what turns "it didn't work" into "merge these two".
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
    /// Every set of video game references that look like the same work under
    /// <see cref="TitleNormalizer.NormalizeLoose"/> but are separate documents - the state a provider change
    /// leaves behind, and one a reference-data import can create outright (it matches documents by provider
    /// id, so an export whose games are IGDB-linked lands beside a target's RAWG-linked copies of the same
    /// games rather than merging into them).
    /// <para>
    /// A duplicate is not cosmetic: tenants' items point at whichever document existed when they linked, so
    /// the ratings, cover and provider ids a work has are split across two records, and Explore excludes on
    /// only one of them.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<IReadOnlyList<VideoGameReferenceModel>>> FindDuplicateVideoGameReferencesAsync()
    {
        var references = await videoGameReferenceRepository.FindAllAsync();
        return references
            .GroupBy(r => TitleNormalizer.NormalizeLoose(r.Title))
            .Where(group => group.Count() > 1)
            // a same-name pair from genuinely different years (a remake) is a real pair of works, not a
            // duplicate - the same year rule adoption confirms with
            .Where(group => group.Select(r => r.Year).Distinct().Count() == 1)
            .Select(IReadOnlyList<VideoGameReferenceModel> (group) => group.OrderBy(r => r.Id, StringComparer.Ordinal).ToList())
            .ToList();
    }

    /// <summary>
    /// Folds one duplicate reference document into another: the surviving document gains whatever the other
    /// knew that it didn't, every tenant item pointing at the absorbed one is re-pointed, and the absorbed
    /// document is deleted.
    /// <para>
    /// The merge direction is "fill the gaps in <paramref name="keepId"/>, never overwrite it" - the same rule
    /// <c>SetReferenceLinkAsync</c> and the reference-data import follow, and the only safe one here: where
    /// both documents hold a value for the same provider id or rating source they were written by that
    /// provider about the same work, so either is right, while a field only one of them has is strictly new
    /// information.
    /// </para>
    /// <para>
    /// Re-pointing the tenant items is the step that makes this more than tidying. A tenant's
    /// <c>ReferenceId</c> is what every hydrated cover, rating and Explore exclusion goes through, so deleting
    /// the absorbed document without moving its dependants would silently blank all three for those items.
    /// </para>
    /// </summary>
    public async Task<(VideoGameReferenceModel Kept, long ItemsRepointed)> MergeVideoGameReferencesAsync(string keepId, string mergeId)
    {
        if (keepId == mergeId) throw new ArgumentException("A reference cannot be merged into itself.", nameof(mergeId));

        var keep = await videoGameReferenceRepository.FindByIdAsync(keepId)
                   ?? throw new ArgumentException($"No video game reference with id '{keepId}'.", nameof(keepId));
        var absorbed = await videoGameReferenceRepository.FindByIdAsync(mergeId)
                       ?? throw new ArgumentException($"No video game reference with id '{mergeId}'.", nameof(mergeId));

        // computed *before* the ids are unioned, and that order is load-bearing: the "is this a RAWG image"
        // test is "does this document carry a rawg id", which is only true of each document while they are
        // still separate. Merge the ids first and the survivor carries a rawg id whatever its own cover
        // actually is, so its IGDB box art would pass the test and the real key art would be dropped.
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

        // the absorbed document goes first: while both exist they hold the same provider ids, and the unique
        // partial indexes on external_ids.* reject the second writer of any of them.
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
    /// Which of two duplicate documents' covers the merged one keeps: <b>a RAWG-linked document's image wins</b>,
    /// then the survivor's own, then the absorbed one's.
    /// <para>
    /// The same rule <see cref="PreferredImageUrl"/> applies to a refresh, for the same reason and with the
    /// same test: RAWG's <c>background_image</c> is curated landscape key art whose CDN still serves those
    /// URLs even though its API doesn't, IGDB's portrait box art is a downgrade, and a RAWG URL cannot be
    /// recomputed from the RAWG id without RAWG's API - so losing one here is permanent, while keeping it
    /// costs nothing. A merge is precisely where that loss would otherwise happen silently: the duplicate pair
    /// this feature exists to fix is typically one RAWG-era document and one IGDB-era one, and "keep the
    /// survivor's, fill in from the other" would throw the key art away whenever the admin picked the IGDB
    /// document to survive.
    /// </para>
    /// <para>
    /// Here the id test is exact rather than a proxy: each document is still separate and was written by one
    /// provider, so "carries a rawg id" really does mean "this image came from RAWG". That is only true before
    /// the ids are unioned - see the caller.
    /// </para>
    /// </summary>
    private static string? MergedImageUrl(VideoGameReferenceModel keep, VideoGameReferenceModel absorbed) =>
        RawgImageOf(keep) ?? RawgImageOf(absorbed) ?? keep.ImageUrl ?? absorbed.ImageUrl;

    private static string? RawgImageOf(VideoGameReferenceModel reference) =>
        reference.ExternalIds.ContainsKey(RatingSourceCatalog.Rawg) && !string.IsNullOrEmpty(reference.ImageUrl)
            ? reference.ImageUrl
            : null;

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
