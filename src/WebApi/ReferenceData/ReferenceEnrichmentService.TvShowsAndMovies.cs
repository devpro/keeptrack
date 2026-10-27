using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

public partial class ReferenceEnrichmentService
{
    /// <summary>
    /// TMDB credits list dozens of people, and a page shows only the top-billed cast, so only that many are stored.
    /// </summary>
    private const int MaxCastMembers = 15;

    // the two rating source keys of movies and TV, used as Ratings keys, the primary being resolved by GetPrimaryRatingSourceAsync
    private const string TmdbRatingSource = RatingSourceCatalog.Tmdb;

    private const string ImdbRatingSource = RatingSourceCatalog.Imdb;

    /// <summary>
    /// The <c>Ratings</c> map from a TMDB vote aggregate.
    /// <c>vote_average</c> 0 with <c>vote_count</c> 0 means nobody rated the title, so it is omitted rather than shown and sorted as a zero.
    /// IMDb is added by <see cref="AddImdbRatingAsync"/>, since it needs an OMDb call.
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
    /// Adds an <c>imdb</c> entry (IMDb's 0 to 10 rating through OMDb, keyed by the IMDb id TMDB exposes) to <paramref name="ratings"/>,
    /// and stamps the attempt on <paramref name="ratingsCheckedAt"/>.
    /// Nothing is added without an IMDb id, an OMDb key, budget for <paramref name="priority"/>, or a rating, IMDb being best effort.
    /// The id stays in <c>ExternalIds["imdb"]</c>, so the sync backfills a missing rating with one OMDb call (see <see cref="RefreshMovieReferenceAsync"/>).
    /// <para>
    /// The attempt is stamped whenever OMDb answered, with or without a value, so the backfill does not buy the same answer every pass.
    /// A call that never happened leaves no stamp (<see cref="OmdbLookupResult.Attempted"/>),
    /// and the result is returned whole since callers need that distinction (<see cref="RebuildRatingsAsync"/>).
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
    /// Rebuilds a reference's <c>Ratings</c> from a fresh TMDB fetch: TMDB's vote plus a new IMDb lookup, for both full-fetch refresh paths.
    /// <para>
    /// It keeps the known IMDb value when OMDb was never asked (no key, spent budget, failed request),
    /// or the rebuild would discard a rating that cost a call, on the very days the budget is tight.
    /// An answer of "OMDb has nothing" clears it.
    /// </para>
    /// <para>
    /// Unlike the no-change shortcut, a spent budget does not hold <c>LastEnrichedAt</c> back here (see <see cref="ImdbBackfillOutcome.Deferred"/>):
    /// details, cast and people were refreshed, and paying all of it again to retry one OMDb call is the wrong trade.
    /// The reference keeps its TMDB rating, so next time it takes the cheap shortcut, retrying IMDb for one <c>/changes</c> call.
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
    /// The cheap IMDb backfill of the no-change shortcut (see <see cref="RefreshMovieReferenceAsync"/>),
    /// adding a rating only when the reference has none, so a rated one makes no OMDb call.
    /// A missing IMDb id comes from TMDB's external ids (<paramref name="fetchImdbId"/>), not the full fetch the shortcut avoids, and is stored on <paramref name="externalIds"/>.
    /// <para>
    /// The guards run cheapest first, each ruling out a different waste.
    /// A title asked about within <see cref="RatingSourceCatalog.RatingReattemptAfter"/> is skipped before the id lookup, saving both calls for a title IMDb has nothing for.
    /// Then the budget: without an OMDb call, the id lookup would be wasted, so the backfill is deferred (<see cref="ImdbBackfillOutcome.Deferred"/>).
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

        // The allowance can also run out during this call, through another replica or OMDb's "Request limit reached!" (see OmdbClient.HandleRejectedKeyAsync).
        // Reading the budget again tells that apart from the other empty answers:
        // a missing key would pin every reference at the head of the queue forever, and a transport failure is left to the next pass.
        return !lookup.Attempted && omdbCallBudget.IsExhausted(OmdbCallPriority.Background)
            ? ImdbBackfillOutcome.Deferred
            : ImdbBackfillOutcome.Complete;
    }

    /// <summary>
    /// What a pass's IMDb backfill (<see cref="BackfillImdbRatingAsync"/>) did, deciding whether tenant items need a new stamp and whether the reference may be stamped enriched.
    /// </summary>
    private enum ImdbBackfillOutcome
    {
        /// <summary>
        /// Nothing left to do: the reference has an IMDb rating, was asked recently, has no IMDb id, or OMDb has nothing.
        /// It is as enriched as it can be, so <c>LastEnrichedAt</c> is stamped and it leaves the head of the queue.
        /// </summary>
        Complete,

        /// <summary>OMDb answered with a rating, to copy onto every linked tenant item.</summary>
        Backfilled,

        /// <summary>
        /// The day's OMDb allowance was spent, so the lookup never happened and the reference still needs one.
        /// <c>LastEnrichedAt</c> is left untouched, since stamping a skipped document would hide it from <c>FindStaleAsync</c> for a whole window,
        /// with an IMDb id, no rating and no record of being asked.
        /// <para>
        /// This case limits itself: the allowance renews at UTC midnight, so holding these at the head costs one <c>/changes</c> call each per pass,
        /// and the next affordable calls go to references missing a rating.
        /// That bound is why it is not the starvation the <c>StampsItAsChecked_WhenNoProviderIdCouldBeResolved</c> rule prevents.
        /// </para>
        /// </summary>
        Deferred
    }

    /// <summary>
    /// Whether <paramref name="source"/> was asked recently enough that asking again would buy the same answer.
    /// Only the background backfills read it, since an admin's link or an Explore add always asks, someone waiting and spending from the reserve.
    /// </summary>
    private static bool AttemptedRecently(IReadOnlyDictionary<string, DateTime> ratingsCheckedAt, string source) =>
        ratingsCheckedAt.TryGetValue(source, out var attemptedAt)
        && DateTime.UtcNow - attemptedAt < RatingSourceCatalog.RatingReattemptAfter;

    /// <summary>
    /// The (value, scale, source) copied onto tenant items: the primary source's value, or none (see <see cref="GetPrimaryRatingSourceAsync"/>).
    /// <para>
    /// The source is returned even without a value, since it records which source the copy came from,
    /// which lets the recompute tell an item on the selected source from one needing a new stamp.
    /// Without it every unrated item would look stale forever.
    /// </para>
    /// </summary>
    private static (double? Value, double? Scale, string Source) PrimaryRating(IReadOnlyDictionary<string, ReferenceRatingModel> ratings, string source) =>
        ratings.TryGetValue(source, out var r) ? (r.Value, r.Scale, source) : (null, null, source);

    /// <summary>
    /// The local half of "check for reference match":
    /// the local references only (by title and year, else title alone, against every confirmed alias, see <see cref="TvShowReferenceModel.MatchedAliases"/>),
    /// never TMDB, one indexed lookup.
    /// It does not stop at an existing link, so a tenant unhappy with a match fixes the title or year and checks again.
    /// It updates this tenant's document only (see <see cref="ReferenceLinkTarget"/>),
    /// and a match also sets <see cref="TvShowModel.Year"/> to the reference's year, still editable.
    /// Without a match, an existing link is cleared, since the edit says it is wrong,
    /// which also returns the item to the admin queue (<see cref="ITvShowRepository.FindDistinctUnresolvedTitleYearsAsync"/>).
    /// </summary>
    public async Task<TvShowModel> TryLinkExistingTvShowReferenceAsync(TvShowModel model)
    {
        // an empty title matches nothing, and falling through would unlink a linked item, so empty input does nothing
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // The title-only fallback runs only without a year, FindByTitleYearAsync(title, null) matching only a reference without a year either.
        // With an unconfirmed year, the fallback would ignore it and risk a namesake ("Road House" 1989 or 2024), so the item stays unresolved.
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

        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await tvShowRepository.UpdateAsync(model.Id!, model, model.OwnerId);

        return model;
    }

    /// <summary>
    /// Movie equivalent of <see cref="TryLinkExistingTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<MovieModel> TryLinkExistingMovieReferenceAsync(MovieModel model)
    {
        // see TryLinkExistingTvShowReferenceAsync's empty-title guard
        if (string.IsNullOrWhiteSpace(model.Title)) return model;

        // the title-only fallback never runs with a year (see TryLinkExistingTvShowReferenceAsync)
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

        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));

        model.ReferenceId = reference.Id;
        model.Title = reference.Title;
        if (reference.Year is not null) model.Year = reference.Year;
        model.ReferenceRating = ratingValue;
        model.ReferenceRatingScale = ratingScale;
        model.ReferenceRatingSource = ratingSource;
        await movieRepository.UpdateAsync(model.Id!, model, model.OwnerId);

        return model;
    }

    /// <summary>
    /// The admin's unlink: clears this item's <see cref="TvShowModel.ReferenceId"/> and, unlike a cleared match, deletes the shared reference, since the admin found it bad data.
    /// Other items still pointing at it are not checked, a rare case accepted rather than guarded.
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
    /// Best-effort automatic match for a TV show: links a single <b>confirmed</b> match and leaves anything else for the admin queue.
    /// <para>
    /// Confirmed means <see cref="ReferenceMatchRules.ConfirmedMatches"/>: a candidate named this show and agreeing about the year, <b>not</b> TMDB returning one result.
    /// </para>
    /// <para>
    /// Counting would refuse ordinary shows, since TMDB's search is fuzzy: <c>The Bear</c> (2022) returns eight results and <c>Dark</c> (2017) fifteen, the show first in both.
    /// </para>
    /// <para>
    /// It would also link unrelated ones: <c>search/tv?query=Fallout&amp;first_air_date_year=2025</c> returns only "Thirst Trap: The Fame. The Fantasy. The Fallout.",
    /// and a wrong link is silent data loss.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveTvShowAsync(TvShowModel item)
    {
        var title = item.Title;
        var year = item.Year;

        // never call the provider with an empty title, which has nothing to search with
        if (string.IsNullOrWhiteSpace(title)) return;

        // A year is required for any automatic link (owner's rule), as for video games.
        // TMDB holds six shows named "The Office", so a title alone identifies nothing, and without a year the item waits for "check for reference match".
        if (year is null) return;

        // a reference confirmed for this (title, year) is the answer, asked before TMDB (see TryLinkKnownReferenceAsync)
        if (await TryLinkKnownReferenceAsync(
                () => tvShowReferenceRepository.FindByTitleYearAsync(title, year),
                reference => WriteTvShowLinkAsync(reference, ReferenceLinkTarget.Item(item.Id!, item.OwnerId))))
        {
            return;
        }

        var candidates = await SearchForAutomaticMatchAsync(tmdbClient.SearchTvShowAsync(title, year), "TV show", title);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveTvShowAsync(title, year, matches[0].TmdbId, ReferenceLinkTarget.Item(item.Id!, item.OwnerId));
    }

    /// <summary>
    /// Best-effort automatic match for movies, under the rule of <see cref="TryAutoResolveTvShowAsync"/>.
    /// <para>
    /// <c>Heat</c> (1995) returns fourteen results and <c>Alien</c> (1979) nine, the film first in each, and TMDB holds a "Road House" from 1989 and one from 2024.
    /// </para>
    /// </summary>
    public async Task TryAutoResolveMovieAsync(MovieModel item)
    {
        var title = item.Title;
        var year = item.Year;

        if (string.IsNullOrWhiteSpace(title)) return; // see TryAutoResolveTvShowAsync
        if (year is null) return; // a year is required, as for shows

        if (await TryLinkKnownReferenceAsync(
                () => movieReferenceRepository.FindByTitleYearAsync(title, year),
                reference => WriteMovieLinkAsync(reference, ReferenceLinkTarget.Item(item.Id!, item.OwnerId))))
        {
            return;
        }

        var candidates = await SearchForAutomaticMatchAsync(tmdbClient.SearchMovieAsync(title, year), "movie", title);
        var matches = ReferenceMatchRules.ConfirmedMatches(candidates, title, year);
        if (matches.Count != 1) return;
        await ResolveMovieAsync(title, year, matches[0].TmdbId, ReferenceLinkTarget.Item(item.Id!, item.OwnerId));
    }

    /// <summary>
    /// "Check for reference match" for TV shows: an established local match first, else TMDB under the rule of automatic resolution.
    /// <para>
    /// The local half alone cannot keep the button's promise ("Not right? Edit the title or year below, then check again.").
    /// An item created without a year has no reference, resolution refusing to act, so correcting it locally would find nothing forever.
    /// </para>
    /// <para>
    /// It adds no guessing: it links exactly what <see cref="TryAutoResolveTvShowAsync"/> would have on create.
    /// </para>
    /// </summary>
    public async Task<TvShowModel> LinkTvShowReferenceAsync(TvShowModel model)
    {
        model = await TryLinkExistingTvShowReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        // resolution writes the link to the stored item, so the caller's copy is read again
        await TryAutoResolveTvShowAsync(model);
        return await tvShowRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>Movie equivalent of <see cref="LinkTvShowReferenceAsync"/>.</summary>
    public async Task<MovieModel> LinkMovieReferenceAsync(MovieModel model)
    {
        model = await TryLinkExistingMovieReferenceAsync(model);
        if (!string.IsNullOrEmpty(model.ReferenceId)) return model;

        await TryAutoResolveMovieAsync(model);
        return await movieRepository.FindOneAsync(model.Id!, model.OwnerId) ?? model;
    }

    /// <summary>
    /// Resolves a title and year to a TMDB show id, an admin's pick or the confirmed automatic match, upserts the reference and links the records <paramref name="target"/> names.
    /// </summary>
    public async Task<TvShowReferenceModel> ResolveTvShowAsync(string title, int? year, string tmdbId, ReferenceLinkTarget target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title); // mapped to a 400 by ApiExceptionFilterAttribute

        var details = await tmdbClient.GetTvShowDetailsAsync(tmdbId)
                      ?? throw new InvalidOperationException($"TMDB show {tmdbId} could not be fetched.");
        var cast = await tmdbClient.GetTvShowCastAsync(tmdbId);

        // The TMDB id is checked first and is authoritative, so two tenants resolving one show under different titles (a translation, a corrected typo) reuse one document.
        // The title-only fallback never runs with a year: it reuses existing.Id for the upsert, so a namesake of another year would be overwritten with this show's data.
        var existing = await tvShowReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await tvShowReferenceRepository.FindByTitleYearAsync(title, year);
        if (existing is null && year is null)
        {
            existing = await tvShowReferenceRepository.FindByTitleAsync(title);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;
        // the IMDb id is stored even without a rating yet, so a later sync backfills it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) externalIds["imdb"] = details.ImdbId;

        var ratings = BuildTmdbRatings(details.VoteAverage, details.VoteCount);
        // carried over rather than restarted, since the stamps keep the backfill from asking OMDb again about a title already answered
        var ratingsCheckedAt = existing?.RatingsCheckedAt ?? [];
        // interactive, since an admin or an Explore add is waiting: it spends the reserve the scheduled passes leave, whatever the last attempt
        await AddImdbRatingAsync(ratings, ratingsCheckedAt, details.ImdbId, OmdbCallPriority.Interactive);

        var model = new TvShowReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            ExternalIds = externalIds,
            // remembers the canonical (title, year) and the one the tenant searched with, so a later tenant typing either matches at once
            MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
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
        await WriteTvShowLinkAsync(saved, target);
        return saved;
    }

    /// <summary>
    /// Points the records <paramref name="target"/> names at <paramref name="reference"/>, carrying its canonical title, year and primary rating across.
    /// </summary>
    private async Task WriteTvShowLinkAsync(TvShowReferenceModel reference, ReferenceLinkTarget target)
    {
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));
        await tvShowRepository.SetReferenceLinkAsync(target, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);
    }

    /// <summary>
    /// Movie equivalent of <see cref="ResolveTvShowAsync"/>.
    /// </summary>
    public async Task<MovieReferenceModel> ResolveMovieAsync(string title, int? year, string tmdbId, ReferenceLinkTarget target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(title);

        var details = await tmdbClient.GetMovieDetailsAsync(tmdbId)
                      ?? throw new InvalidOperationException($"TMDB movie {tmdbId} could not be fetched.");
        var cast = await tmdbClient.GetMovieCastAsync(tmdbId);

        // the TMDB id is checked first and is authoritative, and the title-only fallback never runs with a year (see ResolveTvShowAsync)
        var existing = await movieReferenceRepository.FindByExternalIdAsync("tmdb", tmdbId)
                       ?? await movieReferenceRepository.FindByTitleYearAsync(title, year);
        if (existing is null && year is null)
        {
            existing = await movieReferenceRepository.FindByTitleAsync(title);
        }
        var externalIds = existing?.ExternalIds ?? new Dictionary<string, string>();
        externalIds["tmdb"] = tmdbId;
        // the IMDb id is stored even without a rating yet, so a later sync backfills it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) externalIds["imdb"] = details.ImdbId;

        var ratings = BuildTmdbRatings(details.VoteAverage, details.VoteCount);
        // carried over, so a re-resolve keeps what OMDb already answered (see ResolveTvShowAsync)
        var ratingsCheckedAt = existing?.RatingsCheckedAt ?? [];
        // interactive, since an admin or an Explore add is waiting: it spends the reserve the scheduled passes leave, whatever the last attempt
        await AddImdbRatingAsync(ratings, ratingsCheckedAt, details.ImdbId, OmdbCallPriority.Interactive);

        var model = new MovieReferenceModel
        {
            Id = existing?.Id,
            Title = details.Title,
            TitleNormalized = TitleNormalizer.Normalize(details.Title),
            Year = details.Year ?? year,
            Synopsis = details.Synopsis,
            ExternalIds = externalIds,
            // remembers the canonical (title, year) and the one the tenant searched with, so a later tenant typing either matches at once
            MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(existing?.MatchedAliases, (details.Title, details.Year ?? year, null, null), (title, year, null, null)),
            Genres = details.Genres,
            Cast = await ResolveCastAsync(cast),
            Ratings = ratings,
            RatingsCheckedAt = ratingsCheckedAt,
            ImageUrl = details.PosterUrl,
            LastEnrichedAt = DateTime.UtcNow
        };

        var saved = await movieReferenceRepository.UpsertAsync(model);
        await WriteMovieLinkAsync(saved, target);
        return saved;
    }

    /// <summary>Movie equivalent of <see cref="WriteTvShowLinkAsync"/>.</summary>
    private async Task WriteMovieLinkAsync(MovieReferenceModel reference, ReferenceLinkTarget target)
    {
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(reference.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));
        await movieRepository.SetReferenceLinkAsync(target, reference.Id!, reference.Title, reference.Year, ratingValue, ratingScale, ratingSource);
    }

    /// <summary>
    /// Fetches a TV show reference again when TMDB changed it since <see cref="TvShowReferenceModel.LastEnrichedAt"/>,
    /// skipping the per-season fetches otherwise, and stamps <c>LastEnrichedAt</c> so the sync moves on.
    /// Unchanged for a reference without a TMDB id or one TMDB no longer holds.
    /// </summary>
    public async Task<(TvShowReferenceModel Model, bool DataChanged)> RefreshTvShowReferenceAsync(
        TvShowReferenceModel reference, bool fullFetch = false, CancellationToken cancellationToken = default)
    {
        var tmdbId = reference.ExternalIds.GetValueOrDefault("tmdb");
        if (string.IsNullOrEmpty(tmdbId)) return (reference, false);

        // a full fetch while the reference has no ratings, so it backfills one (see RefreshMovieReferenceAsync)
        if (!fullFetch && reference.LastEnrichedAt is not null && reference.Ratings.Count > 0)
        {
            var changed = await tmdbClient.HasTvShowChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                var backfill = await BackfillImdbRatingAsync(reference.Ratings, reference.RatingsCheckedAt, reference.ExternalIds,
                    ct => tmdbClient.GetTvShowImdbIdAsync(tmdbId, ct), cancellationToken);
                // only a pass that finished its work stamps the document enriched (see ImdbBackfillOutcome.Deferred)
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
        // the IMDb id is stored even without a rating yet, so a later sync backfills it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) reference.ExternalIds["imdb"] = details.ImdbId;
        reference.Ratings = await RebuildRatingsAsync(
            reference.Ratings, reference.RatingsCheckedAt, details.VoteAverage, details.VoteCount, details.ImdbId, cancellationToken);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await tvShowReferenceRepository.UpsertAsync(reference);
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.TvShow));
        await tvShowRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    /// <summary>
    /// Movie equivalent of <see cref="RefreshTvShowReferenceAsync"/>.
    /// </summary>
    public async Task<(MovieReferenceModel Model, bool DataChanged)> RefreshMovieReferenceAsync(
        MovieReferenceModel reference, bool fullFetch = false, CancellationToken cancellationToken = default)
    {
        var tmdbId = reference.ExternalIds.GetValueOrDefault("tmdb");
        if (string.IsNullOrEmpty(tmdbId)) return (reference, false);

        // A reference without ratings does the full fetch even when TMDB reports no change, or the change check would skip its backfill forever.
        // A rated reference takes the cheap no-change shortcut, unless asked for a full fetch (see ReferenceSyncWindows.FullFetch).
        if (!fullFetch && reference.LastEnrichedAt is not null && reference.Ratings.Count > 0)
        {
            var changed = await tmdbClient.HasMovieChangedSinceAsync(tmdbId, reference.LastEnrichedAt.Value, cancellationToken);
            if (!changed)
            {
                // nothing changed on TMDB, but a missing IMDb rating is backfilled from the stored IMDb id, without a TMDB fetch
                var backfill = await BackfillImdbRatingAsync(reference.Ratings, reference.RatingsCheckedAt, reference.ExternalIds,
                    ct => tmdbClient.GetMovieImdbIdAsync(tmdbId, ct), cancellationToken);
                // only a pass that finished its work stamps the document enriched (see ImdbBackfillOutcome.Deferred)
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
        // the IMDb id is stored even without a rating yet, so a later sync backfills it cheaply
        if (!string.IsNullOrEmpty(details.ImdbId)) reference.ExternalIds["imdb"] = details.ImdbId;
        reference.Ratings = await RebuildRatingsAsync(
            reference.Ratings, reference.RatingsCheckedAt, details.VoteAverage, details.VoteCount, details.ImdbId, cancellationToken);
        reference.ImageUrl = details.PosterUrl ?? reference.ImageUrl;
        reference.MatchedAliases = ReferenceAliasRule.TitleAndYear.Merge(reference.MatchedAliases, (details.Title, reference.Year, null, null));
        reference.LastEnrichedAt = DateTime.UtcNow;

        var saved = await movieReferenceRepository.UpsertAsync(reference);
        // every linked movie's rating copy follows the refreshed rating
        var (ratingValue, ratingScale, ratingSource) = PrimaryRating(saved.Ratings, await GetPrimaryRatingSourceAsync(ReferenceItemType.Movie));
        await movieRepository.SetReferenceRatingAsync(saved.Id!, ratingValue, ratingScale, ratingSource);
        return (saved, true);
    }

    /// <summary>
    /// Upserts each cast member into the shared person_reference collection, deduplicated by TMDB person id, and returns the embedded cast pointing at those documents.
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
