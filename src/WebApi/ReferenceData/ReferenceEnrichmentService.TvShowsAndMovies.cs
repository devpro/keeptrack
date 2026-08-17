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

    // the two rating source keys movies/TV can carry (see RatingSourceCatalog, the single home for these
    // literals); used here purely as the Ratings-dict keys when building the map. Which of the two is the
    // *primary* (denormalized onto the tenant item as the list pill / sort value) is resolved per-domain via
    // GetPrimaryRatingSourceAsync (admin-selectable), not hardcoded here.
    private const string TmdbRatingSource = RatingSourceCatalog.Tmdb;

    private const string ImdbRatingSource = RatingSourceCatalog.Imdb;

    /// <summary>
    /// Builds the reference <c>Ratings</c> map from a TMDB vote aggregate. TMDB returns <c>vote_average</c> 0
    /// with <c>vote_count</c> 0 for a title nobody has rated - that's "no rating", not a genuine zero, so it's
    /// omitted rather than stored (a stored 0 would sort as a real score and render a "0" pill). IMDb is added
    /// separately (<see cref="AddImdbRatingAsync"/>) since it needs an OMDb HTTP call this static builder can't make.
    /// </summary>
    private static Dictionary<string, ReferenceRatingModel> BuildTmdbRatings(double? voteAverage, int? voteCount)
    {
        var ratings = new Dictionary<string, ReferenceRatingModel>();
        if (voteAverage is > 0 && voteCount is > 0)
        {
            ratings[TmdbRatingSource] = new ReferenceRatingModel { Value = voteAverage.Value, Scale = 10, Count = voteCount };
        }
        return ratings;
    }

    /// <summary>
    /// Adds an <c>imdb</c> entry (IMDb's 0-10 aggregate, via OMDb keyed by the IMDb id TMDB exposes) to a
    /// <paramref name="ratings"/> map, and stamps the attempt on <paramref name="ratingsCheckedAt"/>.
    /// Produces nothing when there's no IMDb id, no OMDb key is configured, the daily OMDb budget for
    /// <paramref name="priority"/> is spent, or OMDb has no rating for the title - IMDb is best-effort, its
    /// absence is never an error. The IMDb id itself is stored in the reference's <c>ExternalIds["imdb"]</c>
    /// so the periodic sync can backfill a missing rating cheaply (one OMDb call, no TMDB re-fetch) - see
    /// <see cref="RefreshMovieReferenceAsync"/>.
    /// <para>
    /// The attempt is stamped whenever OMDb actually answered, whether or not it had a value: "OMDb has
    /// nothing for this title" is a fact worth remembering, and remembering it is what stops the backfill
    /// below paying for the same answer every pass. A call that never happened leaves no stamp - the
    /// distinction <see cref="OmdbLookupResult.Attempted"/> exists to carry. The whole lookup result is
    /// returned rather than a bool because that distinction matters to callers too (see
    /// <see cref="RebuildRatingsAsync"/>).
    /// </para>
    /// </summary>
    private async Task<OmdbLookupResult> AddImdbRatingAsync(
        Dictionary<string, ReferenceRatingModel> ratings,
        Dictionary<string, DateTime> ratingsCheckedAt,
        string? imdbId,
        OmdbCallPriority priority,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(imdbId)) return OmdbLookupResult.NotAttempted;

        var lookup = await omdbClient.GetRatingAsync(imdbId, priority, cancellationToken);
        if (lookup.Attempted) ratingsCheckedAt[ImdbRatingSource] = DateTime.UtcNow;
        if (lookup.Rating is null) return lookup;

        ratings[ImdbRatingSource] = new ReferenceRatingModel { Value = lookup.Rating.Value, Scale = 10, Count = lookup.Rating.Count };
        return lookup;
    }

    /// <summary>
    /// Rebuilds a reference's whole <c>Ratings</c> map from a fresh TMDB fetch: TMDB's own vote plus a
    /// re-fetched IMDb rating. Shared by both full-fetch refresh paths.
    /// <para>
    /// It keeps the IMDb value already on record when OMDb was never actually asked (no key, spent budget, a
    /// failed request), because the rebuild would otherwise silently discard a rating that cost a call to
    /// obtain - and it would do so precisely on the days the budget is tight, leaving the cheap backfill to
    /// buy it back later. An answer of "OMDb has nothing for this title" is a real answer and does clear it.
    /// </para>
    /// <para>
    /// Unlike the no-change short-circuit, a spent budget does *not* hold this path's <c>LastEnrichedAt</c>
    /// back (see <see cref="ImdbBackfillOutcome.Deferred"/>): the expensive half of the work - details, cast
    /// and the person upserts behind it - genuinely completed, so the document really was refreshed, and
    /// re-paying all of it every pass to retry one OMDb call would be the wrong trade. Such a reference is
    /// left with a TMDB rating, which puts it on the cheap short-circuit path next time round, where the
    /// missing imdb value is retried for the cost of a single <c>/changes</c> call.
    /// </para>
    /// </summary>
    private async Task<Dictionary<string, ReferenceRatingModel>> RebuildRatingsAsync(
        Dictionary<string, ReferenceRatingModel> current,
        Dictionary<string, DateTime> ratingsCheckedAt,
        double? voteAverage,
        int? voteCount,
        string? imdbId,
        CancellationToken cancellationToken)
    {
        var knownImdbRating = current.GetValueOrDefault(ImdbRatingSource);
        var rebuilt = BuildTmdbRatings(voteAverage, voteCount);

        var lookup = await AddImdbRatingAsync(rebuilt, ratingsCheckedAt, imdbId, OmdbCallPriority.Background, cancellationToken);
        if (!lookup.Attempted && knownImdbRating is not null) rebuilt[ImdbRatingSource] = knownImdbRating;

        return rebuilt;
    }

    /// <summary>
    /// Cheap imdb-only backfill for the no-change sync short-circuit (see <see cref="RefreshMovieReferenceAsync"/>):
    /// adds an imdb rating only when the reference has none yet, so an already-imdb-rated reference makes no
    /// OMDb call at all. When the reference has no stored imdb id (enriched before IMDb ratings existed), it's
    /// fetched via a cheap TMDB external-ids lookup (<paramref name="fetchImdbId"/>) - not the full details
    /// re-fetch the short-circuit avoids - and stored on <paramref name="externalIds"/> so later syncs skip
    /// that lookup.
    /// <para>
    /// The three guards are ordered cheapest-first, and each rules out a different kind of waste. A title
    /// OMDb was asked about within <see cref="RatingSourceCatalog.RatingReattemptAfter"/> is skipped for free:
    /// a title IMDb genuinely has nothing for used to cost a TMDB *and* an OMDb call on every pass past the
    /// staleness cutoff - forever, since no key was ever written and nothing recorded that we had already
    /// asked. Skipping before the id lookup is what saves both calls, not just the OMDb one. Then the budget:
    /// with no OMDb call available, the external-ids lookup would be a provider call made purely to throw its
    /// answer away, so the whole backfill is deferred to the next pass instead - which is what
    /// <see cref="ImdbBackfillOutcome.Deferred"/> is for.
    /// </para>
    /// </summary>
    private async Task<ImdbBackfillOutcome> BackfillImdbRatingAsync(
        Dictionary<string, ReferenceRatingModel> ratings,
        Dictionary<string, DateTime> ratingsCheckedAt,
        Dictionary<string, string> externalIds,
        Func<CancellationToken, Task<string?>> fetchImdbId,
        CancellationToken cancellationToken)
    {
        if (ratings.ContainsKey(ImdbRatingSource)) return ImdbBackfillOutcome.Complete;
        if (AttemptedRecently(ratingsCheckedAt, ImdbRatingSource)) return ImdbBackfillOutcome.Complete;
        if (omdbCallBudget.IsExhausted(OmdbCallPriority.Background)) return ImdbBackfillOutcome.Deferred;

        var imdbId = externalIds.GetValueOrDefault("imdb");
        if (string.IsNullOrEmpty(imdbId))
        {
            imdbId = await fetchImdbId(cancellationToken);
            if (!string.IsNullOrEmpty(imdbId)) externalIds["imdb"] = imdbId;
        }

        var lookup = await AddImdbRatingAsync(ratings, ratingsCheckedAt, imdbId, OmdbCallPriority.Background, cancellationToken);
        if (lookup.Rating is not null) return ImdbBackfillOutcome.Backfilled;

        // The allowance can also run out *during* this call - another replica spending the last of it, or
        // OMDb's own "Request limit reached!" 401 writing the day off (see OmdbClient.HandleRejectedKeyAsync).
        // Re-reading the budget is what tells that apart from the other reasons a lookup comes back with
        // nothing, none of which are worth re-walking this document for: a missing key can't be retried into
        // working and would pin every reference at the head of the staleness queue permanently, and a
        // transport failure is transient enough to leave to the next ordinary pass.
        return !lookup.Attempted && omdbCallBudget.IsExhausted(OmdbCallPriority.Background)
            ? ImdbBackfillOutcome.Deferred
            : ImdbBackfillOutcome.Complete;
    }

    /// <summary>
    /// What a pass's IMDb backfill (<see cref="BackfillImdbRatingAsync"/>) actually managed to do - which
    /// decides both whether tenant items need re-stamping and, more importantly, whether the reference may be
    /// stamped as enriched at all.
    /// </summary>
    private enum ImdbBackfillOutcome
    {
        /// <summary>
        /// Nothing left to do for this pass: the reference already had an imdb rating, was asked about
        /// recently enough, has no imdb id to ask with, or OMDb answered and has nothing. The reference is as
        /// enriched as it can currently be, so <c>LastEnrichedAt</c> is stamped and it leaves the queue head.
        /// </summary>
        Complete,

        /// <summary>OMDb answered with a rating, which now has to be propagated to every linked tenant item.</summary>
        Backfilled,

        /// <summary>
        /// The day's OMDb allowance was spent, so the lookup never happened and this reference still needs
        /// one. <c>LastEnrichedAt</c> is deliberately left untouched here: stamping a document the pass
        /// admittedly skipped marks it fresh and drops it out of <c>FindStaleAsync</c> for a whole staleness
        /// window (3 days), which is how a deployment ends up with references that hold an imdb id, no imdb
        /// rating and no record of ever having been asked - confirmed in the running app, 509 movie
        /// references in exactly that state the day after a quota-capped pass.
        /// <para>
        /// Unlike every other reason a document goes unenriched, this one is self-limiting: the allowance
        /// renews at UTC midnight, so holding these at the head of the queue costs one cheap TMDB
        /// <c>/changes</c> call each per pass and guarantees the next affordable calls are spent on the
        /// references that are actually missing a rating, rather than on whatever the 3-day rotation happened
        /// to surface. That bound is why this is not the starvation the
        /// <c>StampsItAsChecked_WhenNoProviderIdCouldBeResolved</c> rule exists to prevent.
        /// </para>
        /// </summary>
        Deferred
    }

    /// <summary>
    /// Whether <paramref name="source"/> was asked about recently enough that asking again would just buy the
    /// same answer. Only the background backfills consult this - an admin's manual link or a user's Explore
    /// "add" always asks, because someone is waiting on the answer and Interactive spends from a reserve the
    /// scheduled passes can't touch anyway.
    /// </summary>
    private static bool AttemptedRecently(IReadOnlyDictionary<string, DateTime> ratingsCheckedAt, string source) =>
        ratingsCheckedAt.TryGetValue(source, out var attemptedAt)
        && DateTime.UtcNow - attemptedAt < RatingSourceCatalog.RatingReattemptAfter;

    /// <summary>
    /// The (value, scale, source) to denormalize onto tenant items - the given primary source's value, or no
    /// value when it has none. Shared across every domain (video games/albums/books pass their own primary
    /// key); which source is primary is admin-selectable per domain (see <see cref="GetPrimaryRatingSourceAsync"/>).
    /// <para>
    /// The source travels with the value, and is returned even when that source has no value for this
    /// reference: it records which source the denormalized copy was computed from, which is what lets the
    /// admin "recompute" action tell an item that is already on the selected source from one that still needs
    /// re-stamping. Returning it only alongside a value would leave every unrated item looking permanently
    /// stale and make the recompute's cheap no-op impossible.
    /// </para>
    /// </summary>
    private static (double? Value, double? Scale, string Source) PrimaryRating(IReadOnlyDictionary<string, ReferenceRatingModel> ratings, string source) =>
        ratings.TryGetValue(source, out var r) ? (r.Value, r.Scale, source) : (null, null, source);

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

        // the title-only fallback only fires when the tenant has no year recorded at all - the case it
        // exists for (FindByTitleYearAsync(title, null) can only ever match a reference whose own Year is
        // also null). When the tenant DOES have a year and it simply isn't a confirmed alias, falling back
        // to title-only would ignore that year entirely and risk matching a same-titled but genuinely
        // different reference (e.g. "Road House" 1990 vs. 2024) - don't guess, leave it unresolved instead.
        var reference = await tvShowReferenceRepository.FindByTitleYearAsync(model.Title, model.Year);
        if (reference is null && model.Year is null)
        {
            reference = await tvShowReferenceRepository.FindByTitleAsync(model.Title);
        }

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                model.ReferenceRatingSource = null;
                await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await tvShowRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);

        return model;
    }

    /// <summary>
    /// Movie equivalent of <see cref="TryLinkExistingTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<MovieModel> TryLinkExistingMovieReferenceAsync(MovieModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // see TryLinkExistingTvShowReferenceAsync's own comment - the title-only fallback must not run when
        // the tenant has a specific year that simply has no confirmed alias
        var reference = await movieReferenceRepository.FindByTitleYearAsync(model.Title, model.Year);
        if (reference is null && model.Year is null)
        {
            reference = await movieReferenceRepository.FindByTitleAsync(model.Title);
        }

        if (reference is null)
        {
            if (!string.IsNullOrEmpty(model.ReferenceId))
            {
                model.ReferenceId = string.Empty;
                model.ReferenceRating = null;
                model.ReferenceRatingScale = null;
                model.ReferenceRatingSource = null;
                await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
            }

            return model;
        }

        var originalTitle = model.Title;
        var originalYear = model.Year;
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        await movieRepository.SetReferenceLinkAsync(originalTitle, originalYear, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);

        return model;
    }

    /// <summary>
    /// Admin-triggered "unlink" - clears this tenant's own <see cref="TvShowModel.ReferenceId"/> and, unlike
    /// the implicit clear-on-no-match branch inside <see cref="TryLinkExistingTvShowReferenceAsync"/>,
    /// permanently deletes the shared reference document itself (the whole point: the admin has determined
    /// this specific match was wrong, so the document behind it is bad data, not just wrong for this tenant).
    /// Deliberately doesn't check whether any other tenant document still points at the same reference id -
    /// an accepted, rare edge case, not worth the complexity of guarding against.
    /// </summary>
    public async Task<TvShowModel> UnlinkTvShowReferenceAsync(TvShowModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        model.ReferenceRatingSource = null;
        await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await tvShowReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Movie equivalent of <see cref="UnlinkTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<MovieModel> UnlinkMovieReferenceAsync(MovieModel model)
    {
        var referenceId = model.ReferenceId;
        model.ReferenceId = string.Empty;
        model.ReferenceRating = null;
        model.ReferenceRatingScale = null;
        model.ReferenceRatingSource = null;
        await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);
        if (!string.IsNullOrEmpty(referenceId))
        {
            await movieReferenceRepository.DeleteAsync(referenceId);
        }

        return model;
    }

    /// <summary>
    /// Best-effort automatic match for a TV show: links a single <b>confirmed</b> match and leaves anything
    /// else for the admin queue rather than guessing.
    /// <para>
    /// What counts as confident is <see cref="ReferenceMatchRules.ConfirmedMatches"/>: a candidate actually
    /// named this show, agreeing about the year. It deliberately is <b>not</b> "TMDB returned exactly one
    /// result", which is what this used to be and which reads a property of the <i>search</i> as a property of
    /// the <i>answer</i>. That was wrong in both directions, and both were measured against the live API.
    /// </para>
    /// <para>
    /// It refused ordinary shows, because TMDB's search is a fuzzy match over titles rather than an exact one:
    /// <c>The Bear</c> (2022) comes back with eight results and <c>Dark</c> (2017) with fifteen, the show
    /// itself first and exactly named in both, and not one of them could ever link. This is what the owner
    /// reported as "creating a show with the right title and year does not match".
    /// </para>
    /// <para>
    /// And it linked things nobody had compared: <c>search/tv?query=Fallout&amp;first_air_date_year=2025</c>
    /// returns exactly one result, and it is "Thirst Trap: The Fame. The Fantasy. The Fallout." - the 2024
    /// show being excluded by the year filter is what leaves that alone in the list. Linking it is silent data
    /// loss, since nothing in the app ever says a wrong reference was chosen.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveTvShowAsync(string title, int? year)
    {
        // never call the provider with an empty title - there is nothing to search with
        if (string.IsNullOrWhiteSpace(title)) return;

        // A year is required for any automatic link here (owner's rule, and the same one video games follow).
        // TMDB holds six shows named exactly "The Office" and two "Utopia" three years apart, so a title on
        // its own identifies nothing; supplying a year is a legitimate part of the contract for an immediate
        // match, and without one the item waits for the detail page's "check for reference match".
        if (year is null) return;

        var candidates = await tmdbClient.SearchTvShowAsync(title, year);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveTvShowAsync(title, year, matches[0].TmdbId);
    }

    /// <summary>
    /// Best-effort automatic match for movies - see <see cref="TryAutoResolveTvShowAsync"/>, which this shares
    /// its rule with entirely.
    /// <para>
    /// The same defect was latent here and only looked healthy because a long title happens to narrow TMDB's
    /// fuzzy search to one row. Measured live, <c>Heat</c> (1995) returns fourteen results and <c>Alien</c>
    /// (1979) returns nine, each with the film first and exactly named, and neither linked. The year matters
    /// just as much: TMDB holds a "Road House" from 1989 and another from 2024, both exactly named.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveMovieAsync(string title, int? year)
    {
        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync
        if (year is null) return; // see TryAutoResolveTvShowAsync - a year is required here too

        var candidates = await tmdbClient.SearchMovieAsync(title, year);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveMovieAsync(title, year, matches[0].TmdbId);
    }

    /// <summary>
    /// What the detail page's "check for reference match" does for TV shows: reuse a fact someone already
    /// established, and only when there is none, ask TMDB under the same confirmed-single-match rule automatic
    /// resolution uses - see <see cref="LinkVideoGameReferenceAsync"/>, where this escalation was first added
    /// and where the full rationale lives.
    /// <para>
    /// The local-only half cannot keep the promise the button makes. Its own tooltip reads <i>"Not right? Edit
    /// the title or year below, then check again."</i>, but an item created before its year was known writes
    /// <b>no</b> reference at all - resolution runs on create and now correctly refuses to act without a year -
    /// so from then on there is nothing local for any amount of correcting the title and year to find, and the
    /// button silently does nothing forever.
    /// </para>
    /// <para>
    /// It adds no new guessing: it links exactly what <see cref="TryAutoResolveTvShowAsync"/> would have
    /// linked on create.
    /// </para>
    /// </summary>
    public async Task<TvShowModel> LinkTvShowReferenceAsync(TvShowModel model)
    {
        model = await TryLinkExistingTvShowReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        // resolution propagates by title+year across every tenant's matching item rather than returning this
        // one, so the caller's copy is re-read rather than patched up here
        await TryAutoResolveTvShowAsync(model.Title, model.Year);
        return await tvShowRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>Movie equivalent of <see cref="LinkTvShowReferenceAsync"/>.</summary>
    public async Task<MovieModel> LinkMovieReferenceAsync(MovieModel model)
    {
        model = await TryLinkExistingMovieReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        await TryAutoResolveMovieAsync(model.Title, model.Year);
        return await movieRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
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
        // The title-only fallback below must not run when year is known but simply unconfirmed yet - it
        // reuses existing.Id for the upsert, so falling back across a real year mismatch (e.g. "Road House"
        // 1990 vs. 2024) wouldn't just link wrong, it would overwrite one reference document with the
        // other's data. See TryLinkExistingTvShowReferenceAsync's own comment for the full rationale.
        var existing = await tvShowReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await tvShowReferenceRepository.FindByTitleYearAsync(title, year);
        if (existing is null && year is null)
        {
            existing = await tvShowReferenceRepository.FindByTitleAsync(title);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;
        // store the imdb id even when OMDb has no rating yet, so a later sync can backfill it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) externalIds["imdb"] = details.ImdbId;

        var ratings = BuildTmdbRatings(details.VoteAverage, details.VoteCount);
        // carried over, never restarted: the attempt stamps are what keep the background backfill from
        // re-asking OMDb about a title it already has its answer for, and rebuilding the document from
        // scratch on every re-resolve would throw that memory away.
        var ratingsCheckedAt = existing?.RatingsCheckedAt ?? [];
        // Interactive: an admin is waiting on this link, or a user just tapped "add" in Explore - these come
        // out of the slice of the daily budget the scheduled passes are not allowed to touch, and they ask
        // regardless of when the last attempt was.
        await AddImdbRatingAsync(ratings, ratingsCheckedAt, details.ImdbId, OmdbCallPriority.Interactive);

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
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Episodes = details.Episodes
                .Select(e => new ReferenceEpisodeModel { SeasonNumber = e.SeasonNumber, EpisodeNumber = e.EpisodeNumber, Title = e.Title, AirDate = e.AirDate })
                .ToList(),
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            Ratings = ratings,
            RatingsCheckedAt = ratingsCheckedAt,
            ImageUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await tvShowReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));
        await tvShowRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, ratingValue, ratingScale, ratingSource);
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
        // See ResolveTvShowAsync's own comment for why the title-only fallback must not run when year is
        // known but simply unconfirmed yet.
        var existing = await movieReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await movieReferenceRepository.FindByTitleYearAsync(title, year);
        if (existing is null && year is null)
        {
            existing = await movieReferenceRepository.FindByTitleAsync(title);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;
        // store the imdb id even when OMDb has no rating yet, so a later sync can backfill it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) externalIds["imdb"] = details.ImdbId;

        var ratings = BuildTmdbRatings(details.VoteAverage, details.VoteCount);
        // see ResolveTvShowAsync: carried over so a re-resolve doesn't forget what OMDb has already answered
        var ratingsCheckedAt = existing?.RatingsCheckedAt ?? [];
        // Interactive: an admin is waiting on this link, or a user just tapped "add" in Explore - these come
        // out of the slice of the daily budget the scheduled passes are not allowed to touch, and they ask
        // regardless of when the last attempt was.
        await AddImdbRatingAsync(ratings, ratingsCheckedAt, details.ImdbId, OmdbCallPriority.Interactive);

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
            MatchedAliases = MergeMatchedAliases(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            Ratings = ratings,
            RatingsCheckedAt = ratingsCheckedAt,
            ImageUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await movieReferenceRepository.UpsertAsync(model);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));
        await movieRepository.SetReferenceLinkAsync(title, year, saved.Id!, details.Title, saved.Year, ratingValue, ratingScale, ratingSource);
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

        // see RefreshMovieReferenceAsync: force a full fetch while the reference has no ratings yet, so
        // references linked before ratings existed backfill one instead of being skipped forever.
        if (reference.LastEnrichedAt is not null && reference.Ratings.Count > 0)
        {
            var changed = await tmdbClient.HasTvShowChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                var backfill = await BackfillImdbRatingAsync(reference.Ratings, reference.RatingsCheckedAt, reference.ExternalIds,
                    ct => tmdbClient.GetTvShowImdbIdAsync(tmdbId, ct), cancellationToken);
                // only a pass that actually finished its work may claim the document is enriched - see
                // ImdbBackfillOutcome.Deferred for why the quota case keeps its old stamp
                if (backfill is not ImdbBackfillOutcome.Deferred) reference.LastEnrichedAt = DateTime.UtcNow;
                var refreshed = await tvShowReferenceRepository.UpsertAsync(reference);
                if (backfill is ImdbBackfillOutcome.Backfilled)
                {
                    var (v, s, backfilledSource) = PrimaryRating(refreshed.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));
                    await tvShowRepository.SetReferenceRatingAsync(refreshed.Id!, v, s, backfilledSource);
                }
                return (refreshed, backfill is ImdbBackfillOutcome.Backfilled);
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
        // store the imdb id even when OMDb has no rating yet, so a later sync can backfill it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) reference.ExternalIds["imdb"] = details.ImdbId;
        reference.Ratings = await RebuildRatingsAsync(
            reference.Ratings, reference.RatingsCheckedAt, details.VoteAverage, details.VoteCount, details.ImdbId, cancellationToken);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await tvShowReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));
        await tvShowRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    /// <summary>
    /// Movie equivalent of <see cref="RefreshTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<(MovieReferenceModel Model, bool DataChanged)> RefreshMovieReferenceAsync(MovieReferenceModel reference, CancellationToken cancellationToken = default)
    {
        var tmdbId = reference.ExternalIds.GetValueOrDefault("tmdb");
        if (string.IsNullOrEmpty(tmdbId)) return (reference, false);

        // A reference with no ratings yet must do the full fetch even when TMDB reports no change since the
        // last enrichment - otherwise references linked before ratings existed would never backfill one (the
        // changes pre-check would keep skipping the fetch forever). Every already-rated reference still takes
        // the cheap no-change short-circuit.
        if (reference.LastEnrichedAt is not null && reference.Ratings.Count > 0)
        {
            var changed = await tmdbClient.HasMovieChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                // nothing changed on TMDB, but backfill a missing imdb rating cheaply (one OMDb call, no
                // TMDB details re-fetch) from the imdb id already stored on the reference
                var backfill = await BackfillImdbRatingAsync(reference.Ratings, reference.RatingsCheckedAt, reference.ExternalIds,
                    ct => tmdbClient.GetMovieImdbIdAsync(tmdbId, ct), cancellationToken);
                // only a pass that actually finished its work may claim the document is enriched - see
                // ImdbBackfillOutcome.Deferred for why the quota case keeps its old stamp
                if (backfill is not ImdbBackfillOutcome.Deferred) reference.LastEnrichedAt = DateTime.UtcNow;
                var refreshed = await movieReferenceRepository.UpsertAsync(reference);
                if (backfill is ImdbBackfillOutcome.Backfilled)
                {
                    var (v, s, backfilledSource) = PrimaryRating(refreshed.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));
                    await movieRepository.SetReferenceRatingAsync(refreshed.Id!, v, s, backfilledSource);
                }
                return (refreshed, backfill is ImdbBackfillOutcome.Backfilled);
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
        // store the imdb id even when OMDb has no rating yet, so a later sync can backfill it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) reference.ExternalIds["imdb"] = details.ImdbId;
        reference.Ratings = await RebuildRatingsAsync(
            reference.Ratings, reference.RatingsCheckedAt, details.VoteAverage, details.VoteCount, details.ImdbId, cancellationToken);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = MergeMatchedAliases(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await movieReferenceRepository.UpsertAsync(reference);
        // keep every already-linked tenant movie's denormalized copy current with the refreshed rating
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));
        await movieRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
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
