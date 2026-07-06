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
    public void ComputeNextEpisodes_ProposesTheEpisodeAfterTheHighestWatched()
    {
        var shows = new[] { Show("show-1", "Dark") };
        var episodes = new[]
        {
            Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)),
            Episode("show-1", 1, 2, new DateOnly(2024, 1, 2))
        };

        var result = _service.ComputeNextEpisodes(shows, episodes);

        result.Should().ContainSingle();
        result[0].TvShowTitle.Should().Be("Dark");
        result[0].NextSeasonNumber.Should().Be(1);
        result[0].NextEpisodeNumber.Should().Be(3);
        result[0].LastWatchedAt.Should().Be(new DateOnly(2024, 1, 2));
    }

    [Fact]
    public void ComputeNextEpisodes_ProposesTheFirstEpisodeOfTheNextSeason_WhenTheHighestWatchedEndsASeason()
    {
        var shows = new[] { Show("show-1", "Dark") };
        var episodes = new[] { Episode("show-1", 1, 8, new DateOnly(2024, 1, 1)) };

        var result = _service.ComputeNextEpisodes(shows, episodes);

        // the service only knows the highest (season, episode) watched, not each season's episode count,
        // so "next" is always season N episode M+1 - a documented heuristic, not season-finale-aware.
        result[0].NextSeasonNumber.Should().Be(1);
        result[0].NextEpisodeNumber.Should().Be(9);
    }

    [Fact]
    public void ComputeNextEpisodes_ExcludesFinishedShows()
    {
        var shows = new[] { Show("show-1", "Dark", finishedAt: new DateOnly(2024, 6, 1)) };
        var episodes = new[] { Episode("show-1", 1, 1) };

        var result = _service.ComputeNextEpisodes(shows, episodes);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeNextEpisodes_ExcludesShowsWithNoWatchedEpisodes()
    {
        var shows = new[] { Show("show-1", "Dark") };

        var result = _service.ComputeNextEpisodes(shows, []);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeNextEpisodes_OrdersByLastWatchedDescending()
    {
        var shows = new[] { Show("show-1", "Older"), Show("show-2", "Newer") };
        var episodes = new[]
        {
            Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)),
            Episode("show-2", 1, 1, new DateOnly(2024, 6, 1))
        };

        var result = _service.ComputeNextEpisodes(shows, episodes);

        result.Should().HaveCount(2);
        result[0].TvShowTitle.Should().Be("Newer");
        result[1].TvShowTitle.Should().Be("Older");
    }
}
