using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Import.Parsers;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Imports a TV Time GDPR export (a zip of CSV files) as an upsert: followed shows, per-episode
/// watch history, ratings, favorite/want-to-watch status, comments, and movies discovered through
/// rating/emotion votes and tracking-prod-records.csv's movie watch/want-to-watch/follow events.
/// Every record created or updated is stamped with the authenticated caller's owner id only - nothing
/// in the uploaded file (including TV Time's own internal user id) is ever used to determine ownership.
/// </summary>
public class TvTimeImportService(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    IMovieRepository movieRepository,
    IServiceScopeFactory scopeFactory,
    ILogger<TvTimeImportService> logger)
{
    private static readonly string[] MovieVoteFileNames =
    [
        "ratings-v2-prod-votes.csv",
        "ratings-live-votes.csv",
        "emotions-v2-prod-votes.csv",
        "emotions-live-votes.csv"
    ];

    public async Task<ImportResultDto> ImportAsync(Stream zipStream, string ownerId, Action<ImportStage>? onStageChanged = null)
    {
        onStageChanged?.Invoke(ImportStage.Parsing);

        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

        // followed_tv_show.csv is NOT a complete list of shows the user has a relationship with - it's
        // just one signal among several (confirmed against real export data: shows with real watch
        // history in the tracking files are sometimes entirely absent from this file). Never treat it
        // as the sole source of truth for "which shows exist".
        var followedShows = ReadCsvEntry(archive, "followed_tv_show.csv", FollowedShowsCsvParser.Parse) ?? [];

        // Three overlapping sources of "episode watched on this date", oldest/least complete to newest/most complete.
        // seen_episode_source.csv alone is usually drastically incomplete (only episode-detail-screen taps); the two
        // tracking-prod-records files are TV Time's generic event logs and capture episodes marked watched any other
        // way too. All three are merged and de-duplicated per (show, season, episode) in ImportEpisodesAsync.
        var seenEpisodes = (ReadCsvEntry(archive, "seen_episode_source.csv", SeenEpisodesCsvParser.Parse) ?? [])
            .Concat(ReadCsvEntry(archive, "tracking-prod-records.csv", LegacyEpisodeWatchCsvParser.Parse) ?? [])
            .Concat(ReadCsvEntry(archive, "tracking-prod-records-v2.csv", EpisodeWatchCsvParser.Parse) ?? [])
            .ToList();

        var showRatings = ReadCsvEntry(archive, "tv_show_rate.csv", ShowRatingsCsvParser.Parse) ?? [];
        var showStatuses = ReadCsvEntry(archive, "user_show_special_status.csv", ShowStatusCsvParser.Parse) ?? [];
        var showComments = ReadCsvEntry(archive, "show_comment.csv", ShowCommentsCsvParser.Parse) ?? [];
        var episodeComments = ReadCsvEntry(archive, "episode_comment.csv", EpisodeCommentsCsvParser.Parse) ?? [];
        var showActivity = ReadCsvEntry(archive, "user_tv_show_data.csv", ShowActivityCsvParser.Parse) ?? [];
        var favoriteMovieUuids = ReadCsvEntry(archive, "lists-prod-lists.csv", FavoriteMoviesListParser.Parse) ?? [];

        var movieVotes = MovieVoteFileNames
            .Select(fileName => ReadCsvEntry(archive, fileName, MovieVotesCsvParser.Parse))
            .Where(votes => votes is not null)
            .SelectMany(votes => votes!)
            .ToList();

        // The only source of a movie's watched-date/want-to-watch status: tracking-prod-records.csv's
        // generic event log also carries movie rows (entity_type "movie"), not just episode ones.
        var movieTrackingEvents = ReadCsvEntry(archive, "tracking-prod-records.csv", MovieTrackingEventsCsvParser.Parse) ?? [];

        var enrichment = ShowEnrichment.Build(showRatings, showStatuses, showComments);
        var result = new ImportResultDto();

        // Map every TV Time title to its stable id, so the title-only source files (seen_episode_source.csv
        // for shows; the vote files for movies) resolve to the *same* id as the id-bearing files
        // (followed_tv_show.csv / the tracking logs) instead of being treated as a different item.
        var showIdByTitle = BuildIdByTitle(
            followedShows.Select(s => (s.Title, (string?)s.TvShowId))
                .Concat(seenEpisodes.Select(e => (e.ShowTitle, e.TvShowId))));
        var movieIdByTitle = BuildIdByTitle(movieTrackingEvents.Select(e => (e.MovieName, e.Uuid)));

        onStageChanged?.Invoke(ImportStage.ImportingShows);
        var showIndex = await ImportShowsAsync(ownerId, followedShows, enrichment, showIdByTitle, result);

        onStageChanged?.Invoke(ImportStage.ImportingEpisodes);
        var detailedEpisodeCountByShowTitle = await ImportEpisodesAsync(ownerId, showIndex, seenEpisodes, episodeComments, enrichment, showIdByTitle, result);
        result.ShowsCreated = showIndex.CreatedCount;
        result.ShowsSkipped = showIndex.SkippedCount;
        AnnotateWatchCompleteness(followedShows, showActivity, detailedEpisodeCountByShowTitle, result);

        onStageChanged?.Invoke(ImportStage.ImportingMovies);
        await ImportMoviesAsync(ownerId, movieVotes, movieTrackingEvents, favoriteMovieUuids, movieIdByTitle, result);

        return result;
    }

    private const string TitleTvTimeIdPrefix = "tvtime_title:";

    /// <summary>
    /// Builds a normalized-title -> stable-id lookup from every (title, id) pair that carries an id,
    /// first one wins. Used so a title appearing in a source file that has no id (seen_episode_source.csv,
    /// the movie vote files) still resolves to the id its id-bearing counterpart established.
    /// </summary>
    private static Dictionary<string, string> BuildIdByTitle(IEnumerable<(string Title, string? Id)> entries)
    {
        var map = new Dictionary<string, string>();
        foreach (var (title, id) in entries)
        {
            if (!string.IsNullOrWhiteSpace(id) && !string.IsNullOrWhiteSpace(title))
            {
                map.TryAdd(TitleNormalizer.Normalize(title), id);
            }
        }

        return map;
    }

    /// <summary>
    /// The stable TV Time id to stamp on (and match) a record: the export's own id for that title when
    /// there is one, otherwise a deterministic title-derived fallback (<c>tvtime_title:&lt;normalized&gt;</c>).
    /// The fallback is stable across re-imports because it is derived from the export title, which
    /// reference enrichment never touches - unlike the record's own Title.
    /// </summary>
    private static string ResolveTvTimeId(string title, Dictionary<string, string> idByTitle)
    {
        var key = TitleNormalizer.Normalize(title);
        return idByTitle.TryGetValue(key, out var id) ? id : TitleTvTimeIdPrefix + key;
    }

    private async Task<UpsertIndex<TvShowModel>> ImportShowsAsync(
        string ownerId,
        List<FollowedShowRecord> followedShows,
        ShowEnrichment enrichment,
        Dictionary<string, string> showIdByTitle,
        ImportResultDto result)
    {
        var existing = (await tvShowRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, NewShow(ownerId, string.Empty))).Items;
        var index = new UpsertIndex<TvShowModel>(existing, show => show.Title);

        foreach (var show in followedShows)
        {
            var tvTimeId = ResolveTvTimeId(show.Title, showIdByTitle);

            if (index.TryMatch(tvTimeId, show.Title, out var existingShow))
            {
                await BackfillTvTimeIdAsync(tvShowRepository, index, existingShow, tvTimeId, ownerId);
                index.MarkMatched(existingShow);
                continue;
            }

            var model = NewShow(ownerId, show.Title);
            model.TvTimeId = tvTimeId;
            enrichment.ApplyTo(model, show.TvShowId);

            var created = await tvShowRepository.CreateAsync(model);
            model.Id = created.Id;
            index.MarkCreated(model);
            index.Index(model);
            await TryEnrichShowAsync(model);
        }

        return index;
    }

    /// <summary>
    /// Upserts episodes from the merged watch-event sources (see <see cref="ImportAsync"/>), taking the
    /// earliest recorded date per (show, season, episode) when more than one source reports it. A show
    /// with watch history that was never in followed_tv_show.csv is created here rather than skipped -
    /// confirmed against real export data that a show can have genuine watch history without ever
    /// appearing in that file. Returns, per normalized show title, how many distinct episodes got a
    /// watch date - used by <see cref="AnnotateWatchCompleteness"/> to flag shows where TV Time's own
    /// reported total is still higher than what these files captured in detail.
    /// </summary>
    private async Task<Dictionary<string, int>> ImportEpisodesAsync(
        string ownerId,
        UpsertIndex<TvShowModel> showIndex,
        List<SeenEpisodeRecord> seenEpisodes,
        List<EpisodeCommentRecord> episodeComments,
        ShowEnrichment enrichment,
        Dictionary<string, string> showIdByTitle,
        ImportResultDto result)
    {
        var notesByEpisodeKey = episodeComments
            .GroupBy(c => (Title: TitleNormalizer.Normalize(c.ShowTitle), c.SeasonNumber, c.EpisodeNumber))
            .ToDictionary(g => g.Key, g => FormatComments(g.Select(c => (c.CreatedAt, c.Comment))));

        var detailedEpisodeCountByShowTitle = new Dictionary<string, int>();

        foreach (var showGroup in seenEpisodes.GroupBy(e => TitleNormalizer.Normalize(e.ShowTitle)))
        {
            var showTitle = showGroup.First().ShowTitle;
            var tvTimeId = ResolveTvTimeId(showTitle, showIdByTitle);

            if (showIndex.TryMatch(tvTimeId, showTitle, out var show))
            {
                await BackfillTvTimeIdAsync(tvShowRepository, showIndex, show, tvTimeId, ownerId);
                showIndex.MarkMatched(show);
            }
            else
            {
                // A show with genuine watch history but no followed_tv_show.csv row is created here rather
                // than skipped (see ImportEpisodesAsync summary). enrichment.ApplyTo takes the raw TV Time
                // show id (null when the export has none), not the possibly-synthesized tvTimeId.
                var rawShowId = showGroup.Select(e => e.TvShowId).FirstOrDefault(id => !string.IsNullOrEmpty(id));
                show = NewShow(ownerId, showTitle);
                show.TvTimeId = tvTimeId;
                enrichment.ApplyTo(show, rawShowId);

                var created = await tvShowRepository.CreateAsync(show);
                show.Id = created.Id;
                showIndex.MarkCreated(show);
                showIndex.Index(show);
                await TryEnrichShowAsync(show);
            }

            // de-duplicate across the merged sources: one row per (season, episode), earliest date wins
            var episodesWatched = showGroup
                .GroupBy(e => (e.SeasonNumber, e.EpisodeNumber))
                .Select(g => (g.Key.SeasonNumber, g.Key.EpisodeNumber, WatchedAt: g.Min(e => e.WatchedAt)))
                .ToList();

            detailedEpisodeCountByShowTitle[showGroup.Key] = episodesWatched.Count;

            // one bulk fetch per show, so matching each watched episode doesn't need its own database round trip
            var existingEpisodes = (await episodeRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
                    NewEpisode(ownerId, show.Id!, 0, 0)))
                .Items
                .Select(e => (e.SeasonNumber, e.EpisodeNumber))
                .ToHashSet();

            foreach (var seen in episodesWatched)
            {
                // Already imported: leave it as-is (keeps the earliest date a previous import recorded).
                if (existingEpisodes.Contains((seen.SeasonNumber, seen.EpisodeNumber)))
                {
                    result.EpisodesSkipped++;
                    continue;
                }

                var episode = NewEpisode(ownerId, show.Id!, seen.SeasonNumber, seen.EpisodeNumber);
                episode.WatchedAt = DateOnly.FromDateTime(seen.WatchedAt);
                if (notesByEpisodeKey.TryGetValue((showGroup.Key, seen.SeasonNumber, seen.EpisodeNumber), out var notes)) episode.Notes = notes;

                await episodeRepository.CreateAsync(episode);
                result.EpisodesCreated++;
            }
        }

        return detailedEpisodeCountByShowTitle;
    }

    /// <summary>
    /// TV Time's own reported episode count (user_tv_show_data.csv) can still be higher than what the
    /// merged watch-event sources captured in detail, for shows with activity old or unusual enough
    /// that even those logs missed it. Surface that gap in plain language instead of silently importing
    /// a suspiciously short watch history.
    /// </summary>
    private static void AnnotateWatchCompleteness(
        List<FollowedShowRecord> followedShows,
        List<ShowActivityRecord> showActivity,
        Dictionary<string, int> detailedEpisodeCountByShowTitle,
        ImportResultDto result)
    {
        var reportedCountByTvShowId = showActivity.ToDictionary(a => a.TvShowId, a => a.EpisodesSeenCount);

        foreach (var show in followedShows)
        {
            if (!reportedCountByTvShowId.TryGetValue(show.TvShowId, out var reportedCount)) continue;

            var detailedCount = detailedEpisodeCountByShowTitle.GetValueOrDefault(TitleNormalizer.Normalize(show.Title));
            if (reportedCount <= detailedCount) continue;

            result.Warnings.Add($"{show.Title}: {detailedCount} of {reportedCount} episodes imported (bulk actions are not exported by TV Time).");
        }
    }

    /// <summary>
    /// A movie exists in Keeptrack if it appears in *either* the rating/emotion vote files or the
    /// tracking-prod-records.csv movie events - not just the vote files, the same "don't limit
    /// existence to one file" lesson already applied to shows. <see cref="MovieTrackingEventType.Watched"/>
    /// events set <see cref="MovieModel.FirstSeenAt"/> (the earliest one, if there's more than one);
    /// a <see cref="MovieTrackingEventType.WantToWatch"/> event only sets <see cref="MovieModel.WantToWatch"/>
    /// when there's no watched event too, so a since-watched movie doesn't stay flagged as still-to-watch.
    /// </summary>
    private async Task ImportMoviesAsync(
        string ownerId,
        List<MovieVoteRecord> movieVotes,
        List<MovieTrackingEventRecord> movieTrackingEvents,
        HashSet<string> favoriteMovieUuids,
        Dictionary<string, string> movieIdByTitle,
        ImportResultDto result)
    {
        var existing = (await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, NewMovie(ownerId, string.Empty))).Items;
        var index = new UpsertIndex<MovieModel>(existing, movie => movie.Title);

        var votesByTitle = movieVotes.GroupBy(v => TitleNormalizer.Normalize(v.MovieName)).ToDictionary(g => g.Key, g => g.ToList());
        var trackingByTitle = movieTrackingEvents.GroupBy(e => TitleNormalizer.Normalize(e.MovieName)).ToDictionary(g => g.Key, g => g.ToList());

        var titles = votesByTitle.Select(g => (g.Key, Name: g.Value[0].MovieName))
            .Concat(trackingByTitle.Select(g => (g.Key, Name: g.Value[0].MovieName)))
            .GroupBy(x => x.Key)
            .Select(g => g.First());

        foreach (var (key, movieName) in titles)
        {
            var tvTimeId = ResolveTvTimeId(movieName, movieIdByTitle);

            if (index.TryMatch(tvTimeId, movieName, out var existingMovie))
            {
                await BackfillTvTimeIdAsync(movieRepository, index, existingMovie, tvTimeId, ownerId);
                index.MarkMatched(existingMovie);
                continue;
            }

            var model = NewMovie(ownerId, movieName);
            model.TvTimeId = tvTimeId;

            if (votesByTitle.TryGetValue(key, out var votes) && votes.Any(v => favoriteMovieUuids.Contains(v.Uuid)))
            {
                model.IsFavorite = true;
            }

            if (trackingByTitle.TryGetValue(key, out var events))
            {
                var watchDates = events.Where(e => e.EventType == MovieTrackingEventType.Watched).Select(e => e.CreatedAt).ToList();
                if (watchDates.Count > 0) model.FirstSeenAt = DateOnly.FromDateTime(watchDates.Min());
                if (watchDates.Count == 0 && events.Any(e => e.EventType == MovieTrackingEventType.WantToWatch)) model.WantToWatch = true;
            }

            var created = await movieRepository.CreateAsync(model);
            model.Id = created.Id;
            index.MarkCreated(model);
            index.Index(model);
            await TryEnrichMovieAsync(model);
        }

        result.MoviesCreated = index.CreatedCount;
        result.MoviesSkipped = index.SkippedCount;
    }

    /// <summary>
    /// One-time adoption of a record created by an import that predated the stable-id matching: it exists
    /// (matched by title) but has no TV Time id yet, so stamp the id on it now, without touching anything
    /// else, so that every subsequent re-import matches it by id instead of title. A no-op for a record
    /// that already carries an id (the steady-state re-import path, which writes nothing at all).
    /// </summary>
    private static async Task BackfillTvTimeIdAsync<TModel>(IDataRepository<TModel> repository, UpsertIndex<TModel> index, TModel model, string tvTimeId, string ownerId)
        where TModel : class, IHasIdAndOwnerId, IHasTvTimeId
    {
        if (!string.IsNullOrEmpty(model.TvTimeId)) return;

        model.TvTimeId = tvTimeId;
        await repository.UpdateAsync(model.Id!, model, ownerId);
        index.Index(model);
    }

    private static TvShowModel NewShow(string ownerId, string title) => new() { OwnerId = ownerId, Title = title };

    private static MovieModel NewMovie(string ownerId, string title) => new() { OwnerId = ownerId, Title = title };

    private static EpisodeModel NewEpisode(string ownerId, string tvShowId, int seasonNumber, int episodeNumber) =>
        new() { OwnerId = ownerId, TvShowId = tvShowId, SeasonNumber = seasonNumber, EpisodeNumber = episodeNumber };

    private static string FormatComments(IEnumerable<(DateTime CreatedAt, string Comment)> comments) =>
        string.Join('\n', comments.OrderBy(c => c.CreatedAt).Select(c => $"{c.CreatedAt:yyyy-MM-dd}: {c.Comment}"));

    /// <summary>
    /// Best-effort background reference-data match for a newly-imported show, fired on its own DI scope
    /// instead of awaited inline - a bulk import creating dozens of shows/movies must not block on a
    /// sequential chain of TMDB HTTP calls (search + details + credits, per item) before finishing. Same
    /// shape already used for single-item creation via <c>TvShowController</c>/<c>MovieController.OnCreatedAsync</c>.
    /// A single show's TMDB lookup failing (rate limit, no network) must never fail the rest of the import.
    /// </summary>
    private Task TryEnrichShowAsync(TvShowModel show)
    {
        var title = show.Title;
        var year = show.Year;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveTvShowAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Reference-data match failed for imported TV show '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    /// <summary>
    /// Movie equivalent of <see cref="TryEnrichShowAsync"/>.
    /// </summary>
    private Task TryEnrichMovieAsync(MovieModel movie)
    {
        var title = movie.Title;
        var year = movie.Year;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveMovieAsync(title, year);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Reference-data match failed for imported movie '{Title}'.", title);
            }
        });
        return Task.CompletedTask;
    }

    private static TResult? ReadCsvEntry<TResult>(ZipArchive archive, string entryName, Func<Stream, TResult> parse)
        where TResult : class
    {
        var entry = archive.GetEntry(entryName);
        if (entry is null) return null;
        using var stream = entry.Open();
        return parse(stream);
    }

    /// <summary>
    /// Resolves each imported show/movie to the existing record it should update, keyed by a stable TV
    /// Time id. This is what makes a re-import idempotent even after reference enrichment has rewritten a
    /// record's stored Title to a provider's canonical name: matching is by the immutable id, never by the
    /// mutable title. It also tallies how many records were created versus skipped, de-duplicated by
    /// reference identity so a show touched in both the followed-shows and episodes phases counts once.
    /// </summary>
    private sealed class UpsertIndex<TModel>
        where TModel : class, IHasTvTimeId
    {
        private readonly Func<TModel, string> _title;
        private readonly Dictionary<string, TModel> _byTvTimeId = [];
        private readonly Dictionary<string, TModel> _byTitle = [];
        private readonly HashSet<TModel> _created = [];
        private readonly HashSet<TModel> _skipped = [];

        public UpsertIndex(IEnumerable<TModel> existing, Func<TModel, string> title)
        {
            _title = title;
            foreach (var model in existing)
            {
                Index(model);
            }
        }

        public int CreatedCount => _created.Count;

        public int SkippedCount => _skipped.Count;

        /// <summary>Registers a model under its TV Time id (if set) and its normalized title.</summary>
        public void Index(TModel model)
        {
            if (!string.IsNullOrEmpty(model.TvTimeId)) _byTvTimeId[model.TvTimeId] = model;
            _byTitle.TryAdd(TitleNormalizer.Normalize(_title(model)), model);
        }

        /// <summary>
        /// Matches an imported item to an existing record. A hit on <paramref name="tvTimeId"/> is the
        /// steady-state path. The title fallback fires only for a record that has no TV Time id yet - one
        /// created by an import predating this feature - so it gets adopted (and back-filled) exactly once
        /// rather than duplicated; a record that already carries a *different* id is left alone, so two
        /// genuinely different items sharing a title are never collapsed into one.
        /// </summary>
        public bool TryMatch(string tvTimeId, string title, out TModel model)
        {
            if (_byTvTimeId.TryGetValue(tvTimeId, out model!)) return true;
            if (_byTitle.TryGetValue(TitleNormalizer.Normalize(title), out model!) && string.IsNullOrEmpty(model.TvTimeId)) return true;

            model = null!;
            return false;
        }

        public void MarkCreated(TModel model) => _created.Add(model);

        public void MarkMatched(TModel model)
        {
            // A record created earlier in this same run is not a pre-existing "skip".
            if (!_created.Contains(model)) _skipped.Add(model);
        }
    }

    /// <summary>
    /// Per-show rating/favorite/want-to-watch/notes, keyed by TV Time's show id. Built once from
    /// tv_show_rate.csv/user_show_special_status.csv/show_comment.csv and applied both to shows found
    /// via followed_tv_show.csv and to shows discovered only through episode watch history.
    /// </summary>
    private sealed class ShowEnrichment(
        Dictionary<string, float> ratingByShowId,
        HashSet<string> favoriteShowIds,
        HashSet<string> wantToWatchShowIds,
        Dictionary<string, string> notesByShowId)
    {
        public static ShowEnrichment Build(List<ShowRatingRecord> showRatings, List<ShowStatusRecord> showStatuses, List<ShowCommentRecord> showComments) =>
            new(
                showRatings.GroupBy(r => r.TvShowId).ToDictionary(g => g.Key, g => g.Last().Rating),
                showStatuses.Where(s => s.Status == ShowStatusCsvParser.FavoriteStatus).Select(s => s.TvShowId).ToHashSet(),
                showStatuses.Where(s => s.Status == ShowStatusCsvParser.ForLaterStatus).Select(s => s.TvShowId).ToHashSet(),
                showComments.GroupBy(c => c.TvShowId).ToDictionary(g => g.Key, g => FormatComments(g.Select(c => (c.CreatedAt, c.Comment)))));

        public void ApplyTo(TvShowModel show, string? tvShowId)
        {
            if (tvShowId is null) return;

            if (ratingByShowId.TryGetValue(tvShowId, out var rating)) show.Rating = rating;
            if (favoriteShowIds.Contains(tvShowId)) show.IsFavorite = true;
            if (wantToWatchShowIds.Contains(tvShowId)) show.WantToWatch = true;
            if (notesByShowId.TryGetValue(tvShowId, out var notes)) show.Notes = notes;
        }
    }
}
