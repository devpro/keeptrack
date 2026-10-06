using System.IO.Compression;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Import.Parsers;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Imports a TV Time GDPR export (a zip of CSV files) as an upsert: followed shows, episode watch history, ratings, favorite and want-to-watch status, comments, and movies found through votes and tracking events.
/// Every record is stamped with the authenticated caller's owner id, never with anything from the file, TV Time's own user id included.
/// </summary>
public class TvTimeImportService(
    ITvShowRepository tvShowRepository,
    IEpisodeRepository episodeRepository,
    IMovieRepository movieRepository,
    IServiceScopeFactory scopeFactory,
    ILogger<TvTimeImportService> logger)
{
    private static readonly string[] s_movieVoteFileNames =
    [
        "ratings-v2-prod-votes.csv",
        "ratings-live-votes.csv",
        "emotions-v2-prod-votes.csv",
        "emotions-live-votes.csv"
    ];

    public async Task<ImportResultDto> ImportAsync(Stream zipStream, string ownerId, Func<ImportStage, Task>? onStageChanged = null)
    {
        if (onStageChanged is not null) await onStageChanged(ImportStage.Parsing);

        await using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

        // followed_tv_show.csv is one signal among several, not the complete list of shows: shows with watch history in the tracking files can be absent from it
        var followedShows = ReadCsvEntry(archive, "followed_tv_show.csv", FollowedShowsCsvParser.Parse) ?? [];

        // Three overlapping sources of episode watch dates, least complete first: seen_episode_source.csv only holds episode screen taps, while the two tracking logs capture every other way.
        // ImportEpisodesAsync merges them and deduplicates per (show, season, episode).
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

        var movieVotes = s_movieVoteFileNames
            .Select(fileName => ReadCsvEntry(archive, fileName, MovieVotesCsvParser.Parse))
            .Where(votes => votes is not null)
            .SelectMany(votes => votes!)
            .ToList();

        // the only source of a movie's watch date and want-to-watch status: tracking-prod-records.csv also carries entity_type "movie" rows
        var movieTrackingEvents = ReadCsvEntry(archive, "tracking-prod-records.csv", MovieTrackingEventsCsvParser.Parse) ?? [];

        var enrichment = ShowEnrichment.Build(showRatings, showStatuses, showComments);
        var result = new ImportResultDto();

        // every TV Time title mapped to its stable id, so the files with titles only (seen episodes, votes) resolve to the same id as those carrying ids
        var showIdByTitle = BuildIdByTitle(
            followedShows.Select(s => (s.Title, (string?)s.TvShowId))
                .Concat(seenEpisodes.Select(e => (e.ShowTitle, e.TvShowId))));
        var movieIdByTitle = BuildIdByTitle(movieTrackingEvents.Select(e => (e.MovieName, e.Uuid)));

        if (onStageChanged is not null) await onStageChanged(ImportStage.ImportingShows);
        var showIndex = await ImportShowsAsync(ownerId, followedShows, enrichment, showIdByTitle);

        if (onStageChanged is not null) await onStageChanged(ImportStage.ImportingEpisodes);
        var detailedEpisodeCountByShowTitle = await ImportEpisodesAsync(ownerId, showIndex, seenEpisodes, episodeComments, enrichment, showIdByTitle, result);
        result.ShowsCreated = showIndex.CreatedCount;
        result.ShowsSkipped = showIndex.SkippedCount;
        AnnotateWatchCompleteness(followedShows, showActivity, detailedEpisodeCountByShowTitle, result);

        if (onStageChanged is not null) await onStageChanged(ImportStage.ImportingMovies);
        await ImportMoviesAsync(ownerId, movieVotes, movieTrackingEvents, favoriteMovieUuids, movieIdByTitle, result);

        return result;
    }

    private const string TitleTvTimeIdPrefix = "tvtime_title:";

    /// <summary>
    /// A lookup from normalized title to stable id, from every (title, id) pair carrying an id, the first winning.
    /// A title from a file without ids (seen_episode_source.csv, the movie votes) then resolves to the id its counterpart established.
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
    /// The stable TV Time id stamped on a record and matched on: the export's id for that title, or else a deterministic one derived from it (<c>tvtime_title:&lt;normalized&gt;</c>).
    /// The fallback is stable across re-imports, derived from the export title, which reference resolution never touches, unlike the record's title.
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
        Dictionary<string, string> showIdByTitle)
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
    /// Upserts episodes from the merged watch sources (see <see cref="ImportAsync"/>), the earliest date winning per (show, season, episode).
    /// A show with watch history absent from followed_tv_show.csv is created rather than skipped.
    /// Returns how many distinct episodes got a date per normalized title, so <see cref="AnnotateWatchCompleteness"/> flags shows where TV Time's total is higher.
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
                // created rather than skipped, and enrichment.ApplyTo takes the raw TV Time show id, null when absent, not a derived tvTimeId
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

            // one row per (season, episode) across the merged sources, the earliest date winning
            var episodesWatched = showGroup
                .GroupBy(e => (e.SeasonNumber, e.EpisodeNumber))
                .Select(g => (g.Key.SeasonNumber, g.Key.EpisodeNumber, WatchedAt: g.Min(e => e.WatchedAt)))
                .ToList();

            detailedEpisodeCountByShowTitle[showGroup.Key] = episodesWatched.Count;

            // one fetch per show, so matching each episode costs no round trip
            var existingEpisodes = (await episodeRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
                    NewEpisode(ownerId, show.Id!, 0, 0)))
                .Items
                .Select(e => (e.SeasonNumber, e.EpisodeNumber))
                .ToHashSet();

            foreach (var seen in episodesWatched)
            {
                // already imported, so the earliest date an earlier import recorded is kept
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
    /// TV Time's episode count (user_tv_show_data.csv) can exceed what the merged sources detail, for activity old or unusual enough that the logs missed it.
    /// The gap is reported in plain language rather than silently importing a short history.
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
    /// A movie exists when it appears in the vote files or in the tracking events, as no single file lists every show either.
    /// The earliest <see cref="MovieTrackingEventType.Watched"/> event sets <see cref="MovieModel.FirstSeenAt"/>.
    /// A <see cref="MovieTrackingEventType.WantToWatch"/> event sets <see cref="MovieModel.WantToWatch"/> only without a watched event, so a movie seen since is not left on the list.
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
    /// Stamps the TV Time id, and nothing else, on a record matched by title that has none, so every later re-import matches it by id.
    /// Does nothing for a record already carrying an id, the usual re-import path, which writes nothing.
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
    /// A best-effort background reference match for an imported show, started on its own DI scope rather than awaited, so a bulk import does not wait on a chain of TMDB calls per item.
    /// Like <c>TvShowController.OnCreatedAsync</c>.
    /// One show's failed lookup never fails the rest of the import.
    /// </summary>
    private Task TryEnrichShowAsync(TvShowModel show)
    {
        var title = show.Title;
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveTvShowAsync(show);
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
        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var enrichmentService = scope.ServiceProvider.GetRequiredService<ReferenceEnrichmentService>();
                await enrichmentService.TryAutoResolveMovieAsync(movie);
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
    /// Resolves each imported show or movie to the existing record it updates, keyed by a stable TV Time id.
    /// That keeps a re-import idempotent after resolution rewrote a title, since matching uses the id, never the title.
    /// It also counts created and skipped records, by object identity, so a show touched by both the followed-shows and episodes phases counts once.
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

        /// <summary>Registers a model under its TV Time id, if set, and its normalized title.</summary>
        public void Index(TModel model)
        {
            if (!string.IsNullOrEmpty(model.TvTimeId)) _byTvTimeId[model.TvTimeId] = model;
            _byTitle.TryAdd(TitleNormalizer.Normalize(_title(model)), model);
        }

        /// <summary>
        /// Matches an imported item to an existing record, usually by <paramref name="tvTimeId"/>.
        /// The title fallback only applies to a record with no TV Time id yet, which is adopted and back-filled once rather than duplicated.
        /// A record with a different id is left alone, so two items sharing a title are never collapsed.
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
            // a record created earlier in this run is not an existing record skipped
            if (!_created.Contains(model)) _skipped.Add(model);
        }
    }

    /// <summary>
    /// Rating, favorite and notes per show, keyed by TV Time's show id.
    /// Built once from tv_show_rate.csv, user_show_special_status.csv and show_comment.csv, and applied to followed shows and to shows found only through watch history.
    /// TV Time's "for_later" status has no counterpart for shows and is not imported.
    /// </summary>
    private sealed class ShowEnrichment(
        Dictionary<string, float> ratingByShowId,
        HashSet<string> favoriteShowIds,
        Dictionary<string, string> notesByShowId)
    {
        public static ShowEnrichment Build(List<ShowRatingRecord> showRatings, List<ShowStatusRecord> showStatuses, List<ShowCommentRecord> showComments) =>
            new(
                showRatings.GroupBy(r => r.TvShowId).ToDictionary(g => g.Key, g => g.Last().Rating),
                showStatuses.Where(s => s.Status == ShowStatusCsvParser.FavoriteStatus).Select(s => s.TvShowId).ToHashSet(),
                showComments.GroupBy(c => c.TvShowId).ToDictionary(g => g.Key, g => FormatComments(g.Select(c => (c.CreatedAt, c.Comment)))));

        public void ApplyTo(TvShowModel show, string? tvShowId)
        {
            if (tvShowId is null) return;

            if (ratingByShowId.TryGetValue(tvShowId, out var rating)) show.Rating = rating;
            if (favoriteShowIds.Contains(tvShowId)) show.IsFavorite = true;
            if (notesByShowId.TryGetValue(tvShowId, out var notes)) show.Notes = notes;
        }
    }
}
