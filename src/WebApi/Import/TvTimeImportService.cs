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

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Imports a TV Time GDPR export (a zip of CSV files) as an upsert: followed shows, per-episode
/// watch history, ratings, favorite/want-to-watch status, comments, and movies discovered through
/// rating/emotion votes. Every record created or updated is stamped with the authenticated caller's
/// owner id only - nothing in the uploaded file (including TV Time's own internal user id) is ever
/// used to determine ownership.
/// </summary>
public class TvTimeImportService(ITvShowRepository tvShowRepository, IEpisodeRepository episodeRepository, IMovieRepository movieRepository)
{
    private static readonly string[] MovieVoteFileNames =
    [
        "ratings-v2-prod-votes.csv",
        "ratings-live-votes.csv",
        "emotions-v2-prod-votes.csv",
        "emotions-live-votes.csv"
    ];

    public async Task<ImportResultDto> ImportAsync(Stream zipStream, string ownerId)
    {
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

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

        var result = new ImportResultDto();

        var showsByTitle = await ImportShowsAsync(ownerId, followedShows, showRatings, showStatuses, showComments, result);
        var detailedEpisodeCountByShowTitle = await ImportEpisodesAsync(ownerId, showsByTitle, seenEpisodes, episodeComments, result);
        AnnotateWatchCompleteness(followedShows, showActivity, detailedEpisodeCountByShowTitle, result);
        await ImportMoviesAsync(ownerId, movieVotes, favoriteMovieUuids, result);

        return result;
    }

    private async Task<Dictionary<string, TvShowModel>> ImportShowsAsync(
        string ownerId,
        List<FollowedShowRecord> followedShows,
        List<ShowRatingRecord> showRatings,
        List<ShowStatusRecord> showStatuses,
        List<ShowCommentRecord> showComments,
        ImportResultDto result)
    {
        var showsByTitle = (await tvShowRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, NewShow(ownerId, string.Empty)))
            .Items
            .ToDictionary(show => NormalizeTitle(show.Title));

        var ratingByShowId = showRatings.GroupBy(r => r.TvShowId).ToDictionary(g => g.Key, g => g.Last().Rating);
        var favoriteShowIds = showStatuses.Where(s => s.Status == ShowStatusCsvParser.FavoriteStatus).Select(s => s.TvShowId).ToHashSet();
        var wantToWatchShowIds = showStatuses.Where(s => s.Status == ShowStatusCsvParser.ForLaterStatus).Select(s => s.TvShowId).ToHashSet();
        var notesByShowId = showComments
            .GroupBy(c => c.TvShowId)
            .ToDictionary(g => g.Key, g => FormatComments(g.Select(c => (c.CreatedAt, c.Comment))));

        foreach (var show in followedShows)
        {
            var key = NormalizeTitle(show.Title);
            var isNew = !showsByTitle.TryGetValue(key, out var model);
            model ??= NewShow(ownerId, show.Title);

            model.Title = show.Title;
            if (ratingByShowId.TryGetValue(show.TvShowId, out var rating)) model.Rating = rating;
            if (favoriteShowIds.Contains(show.TvShowId)) model.IsFavorite = true;
            if (wantToWatchShowIds.Contains(show.TvShowId)) model.WantToWatch = true;
            if (notesByShowId.TryGetValue(show.TvShowId, out var notes)) model.Notes = notes;

            if (await SaveAsync(tvShowRepository, model, ownerId, isNew)) result.ShowsCreated++;
            else result.ShowsUpdated++;

            showsByTitle[key] = model;
        }

        return showsByTitle;
    }

    /// <summary>
    /// Upserts episodes from the merged watch-event sources (see <see cref="ImportAsync"/>), taking the
    /// earliest recorded date per (show, season, episode) when more than one source reports it. Returns,
    /// per normalized show title, how many distinct episodes got a watch date - used by
    /// <see cref="AnnotateWatchCompleteness"/> to flag shows where TV Time's own reported total is still
    /// higher than what these files captured in detail.
    /// </summary>
    private async Task<Dictionary<string, int>> ImportEpisodesAsync(
        string ownerId,
        Dictionary<string, TvShowModel> showsByTitle,
        List<SeenEpisodeRecord> seenEpisodes,
        List<EpisodeCommentRecord> episodeComments,
        ImportResultDto result)
    {
        var notesByEpisodeKey = episodeComments
            .GroupBy(c => (Title: NormalizeTitle(c.ShowTitle), c.SeasonNumber, c.EpisodeNumber))
            .ToDictionary(g => g.Key, g => FormatComments(g.Select(c => (c.CreatedAt, c.Comment))));

        var detailedEpisodeCountByShowTitle = new Dictionary<string, int>();

        foreach (var showGroup in seenEpisodes.GroupBy(e => NormalizeTitle(e.ShowTitle)))
        {
            if (!showsByTitle.TryGetValue(showGroup.Key, out var show) || show.Id is null)
            {
                result.Warnings.Add($"Episode watch history for unknown show '{showGroup.First().ShowTitle}' was skipped.");
                continue;
            }

            // de-duplicate across the merged sources: one row per (season, episode), earliest date wins
            var episodesWatched = showGroup
                .GroupBy(e => (e.SeasonNumber, e.EpisodeNumber))
                .Select(g => (g.Key.SeasonNumber, g.Key.EpisodeNumber, WatchedAt: g.Min(e => e.WatchedAt)))
                .ToList();

            detailedEpisodeCountByShowTitle[showGroup.Key] = episodesWatched.Count;

            // one bulk fetch per show, so matching each watched episode doesn't need its own database round trip
            var existingEpisodes = (await episodeRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
                    NewEpisode(ownerId, show.Id, 0, 0)))
                .Items
                .ToDictionary(e => (e.SeasonNumber, e.EpisodeNumber));

            foreach (var seen in episodesWatched)
            {
                var episodeKey = (seen.SeasonNumber, seen.EpisodeNumber);
                var isNew = !existingEpisodes.TryGetValue(episodeKey, out var episode);
                episode ??= NewEpisode(ownerId, show.Id, seen.SeasonNumber, seen.EpisodeNumber);

                episode.WatchedAt = DateOnly.FromDateTime(seen.WatchedAt);
                if (notesByEpisodeKey.TryGetValue((showGroup.Key, seen.SeasonNumber, seen.EpisodeNumber), out var notes)) episode.Notes = notes;

                if (await SaveAsync(episodeRepository, episode, ownerId, isNew)) result.EpisodesCreated++;
                else result.EpisodesUpdated++;

                existingEpisodes[episodeKey] = episode;
            }
        }

        return detailedEpisodeCountByShowTitle;
    }

    /// <summary>
    /// TV Time only writes a row to seen_episode_source.csv when an episode is marked watched via
    /// its episode-detail screen; episodes marked watched through bulk/season actions never get an
    /// individual date there, even though user_tv_show_data.csv's own episode count includes them.
    /// Surface that gap as a warning instead of silently importing a suspiciously short watch history.
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

            var detailedCount = detailedEpisodeCountByShowTitle.GetValueOrDefault(NormalizeTitle(show.Title));
            if (reportedCount <= detailedCount) continue;

            result.Warnings.Add(
                $"{show.Title}: TV Time reports {reportedCount} episodes seen, but only {detailedCount} have per-episode watch dates in this export " +
                "(TV Time doesn't log detail for episodes marked via bulk/season actions).");
        }
    }

    private async Task ImportMoviesAsync(
        string ownerId,
        List<MovieVoteRecord> movieVotes,
        HashSet<string> favoriteMovieUuids,
        ImportResultDto result)
    {
        var moviesByTitle = (await movieRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, NewMovie(ownerId, string.Empty)))
            .Items
            .ToDictionary(movie => NormalizeTitle(movie.Title));

        foreach (var titleGroup in movieVotes.GroupBy(v => NormalizeTitle(v.MovieName)))
        {
            var isNew = !moviesByTitle.TryGetValue(titleGroup.Key, out var model);
            model ??= NewMovie(ownerId, titleGroup.First().MovieName);

            if (titleGroup.Any(v => favoriteMovieUuids.Contains(v.Uuid))) model.IsFavorite = true;

            if (await SaveAsync(movieRepository, model, ownerId, isNew)) result.MoviesCreated++;
            else result.MoviesUpdated++;

            moviesByTitle[titleGroup.Key] = model;
        }
    }

    /// <summary>
    /// Creates or updates (in place, preserving fields this import doesn't touch) a single model,
    /// shared by the show/episode/movie upserts above.
    /// </summary>
    private static async Task<bool> SaveAsync<TModel>(IDataRepository<TModel> repository, TModel model, string ownerId, bool isNew)
        where TModel : class, IHasIdAndOwnerId
    {
        if (isNew)
        {
            var created = await repository.CreateAsync(model);
            model.Id = created.Id;
            return true;
        }

        await repository.UpdateAsync(model.Id!, model, ownerId);
        return false;
    }

    private static TvShowModel NewShow(string ownerId, string title) => new() { OwnerId = ownerId, Title = title };

    private static MovieModel NewMovie(string ownerId, string title) => new() { OwnerId = ownerId, Title = title };

    private static EpisodeModel NewEpisode(string ownerId, string tvShowId, int seasonNumber, int episodeNumber) =>
        new() { OwnerId = ownerId, TvShowId = tvShowId, SeasonNumber = seasonNumber, EpisodeNumber = episodeNumber };

    private static string NormalizeTitle(string title) => title.Trim().ToLowerInvariant();

    private static string FormatComments(IEnumerable<(DateTime CreatedAt, string Comment)> comments) =>
        string.Join('\n', comments.OrderBy(c => c.CreatedAt).Select(c => $"{c.CreatedAt:yyyy-MM-dd}: {c.Comment}"));

    private static TResult? ReadCsvEntry<TResult>(ZipArchive archive, string entryName, Func<Stream, TResult> parse)
        where TResult : class
    {
        var entry = archive.GetEntry(entryName);
        if (entry is null) return null;
        using var stream = entry.Open();
        return parse(stream);
    }
}
