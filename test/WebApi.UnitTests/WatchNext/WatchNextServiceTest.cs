using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.WebApi.WatchNext;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.WatchNext;

[Trait("Category", "UnitTests")]
public class WatchNextServiceTest
{
    private readonly WatchNextService _service = new();

    private static TvShowModel Show(string id, string title, DateOnly? finishedAt = null) =>
        new() { Id = id, OwnerId = "owner", Title = title, FinishedAt = finishedAt };

    private static EpisodeModel Episode(string showId, int season, int episode, DateOnly? watchedAt = null) =>
        new() { OwnerId = "owner", TvShowId = showId, SeasonNumber = season, EpisodeNumber = episode, WatchedAt = watchedAt };

    [Fact]
    public void ComputeInProgressShows_ReportsTheHighestSeasonAndEpisodeWatched()
    {
        var shows = new[] { Show("show-1", "Dark") };
        var episodes = new[]
        {
            Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)),
            Episode("show-1", 1, 2, new DateOnly(2024, 1, 2))
        };

        var result = _service.ComputeInProgressShows(shows, episodes);

        // deliberately does NOT propose a "next" episode: Keeptrack has no episode-guide data, so it
        // can't tell whether a further episode actually exists yet.
        result.Should().ContainSingle();
        result[0].TvShowTitle.Should().Be("Dark");
        result[0].LastSeasonNumber.Should().Be(1);
        result[0].LastEpisodeNumber.Should().Be(2);
        result[0].LastWatchedAt.Should().Be(new DateOnly(2024, 1, 2));
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesFinishedShows()
    {
        var shows = new[] { Show("show-1", "Dark", finishedAt: new DateOnly(2024, 6, 1)) };
        var episodes = new[] { Episode("show-1", 1, 1) };

        var result = _service.ComputeInProgressShows(shows, episodes);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsWithNoWatchedEpisodes()
    {
        var shows = new[] { Show("show-1", "Dark") };

        var result = _service.ComputeInProgressShows(shows, []);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_OrdersByLastWatchedDescending()
    {
        var shows = new[] { Show("show-1", "Older"), Show("show-2", "Newer") };
        var episodes = new[]
        {
            Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)),
            Episode("show-2", 1, 1, new DateOnly(2024, 6, 1))
        };

        var result = _service.ComputeInProgressShows(shows, episodes);

        result.Should().HaveCount(2);
        result[0].TvShowTitle.Should().Be("Newer");
        result[1].TvShowTitle.Should().Be("Older");
    }
}
