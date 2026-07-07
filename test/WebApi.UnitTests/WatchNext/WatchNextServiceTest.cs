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

    private static TvShowModel Show(string id, string title, TvShowStatus? status = TvShowStatus.Current, string? referenceId = null) =>
        new() { Id = id, OwnerId = "owner", Title = title, Status = status, ReferenceId = referenceId };

    private static EpisodeModel Episode(string showId, int season, int episode, DateOnly? watchedAt = null) =>
        new() { OwnerId = "owner", TvShowId = showId, SeasonNumber = season, EpisodeNumber = episode, WatchedAt = watchedAt };

    private static ReferenceEpisodeModel RefEpisode(int season, int episode, string title, DateOnly? airDate = null) =>
        new() { SeasonNumber = season, EpisodeNumber = episode, Title = title, AirDate = airDate };

    private static TvShowReferenceModel Reference(params ReferenceEpisodeModel[] episodes) => new()
    {
        Title = "Reference Title",
        TitleNormalized = "reference title",
        ExternalIds = new Dictionary<string, string>(),
        Episodes = [.. episodes]
    };

    [Fact]
    public void ComputeInProgressShows_IncludesShowWithAConfirmedAiredUnwatchedNextEpisode()
    {
        var shows = new[] { Show("show-1", "Dark", referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 1, "Ep1"), RefEpisode(1, 2, "Ep2", new DateOnly(2024, 1, 8)))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().ContainSingle();
        result[0].TvShowTitle.Should().Be("Dark");
        result[0].LastSeasonNumber.Should().Be(1);
        result[0].LastEpisodeNumber.Should().Be(1);
        result[0].NextSeasonNumber.Should().Be(1);
        result[0].NextEpisodeNumber.Should().Be(2);
        result[0].NextEpisodeTitle.Should().Be("Ep2");
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesFinishedShows()
    {
        var shows = new[] { Show("show-1", "Dark", status: TvShowStatus.Finished, referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 1) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 2, "Ep2"))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesStoppedShows()
    {
        var shows = new[] { Show("show-1", "Dark", status: TvShowStatus.Stopped, referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 1) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 2, "Ep2"))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsWithNoStatusSet()
    {
        var shows = new[] { Show("show-1", "Dark", status: null, referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 1) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 2, "Ep2"))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsWithNoWatchedEpisodes()
    {
        var shows = new[] { Show("show-1", "Dark", referenceId: "ref-1") };
        var references = new Dictionary<string, TvShowReferenceModel> { ["show-1"] = Reference(RefEpisode(1, 1, "Ep1")) };

        var result = _service.ComputeInProgressShows(shows, [], references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsWithNoReferenceLinked()
    {
        var shows = new[] { Show("show-1", "Dark", referenceId: null) };
        var episodes = new[] { Episode("show-1", 1, 1) };

        var result = _service.ComputeInProgressShows(shows, episodes, new Dictionary<string, TvShowReferenceModel>());

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsFullyCaughtUpWithTheReferenceGuide()
    {
        var shows = new[] { Show("show-1", "Dark", referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 2, new DateOnly(2024, 1, 8)) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            // no episode after S1E2 in the guide at all
            ["show-1"] = Reference(RefEpisode(1, 1, "Ep1"), RefEpisode(1, 2, "Ep2"))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_ExcludesShowsWhoseOnlyUnwatchedEpisodeHasNotAiredYet()
    {
        var shows = new[] { Show("show-1", "Dark", referenceId: "ref-1") };
        var episodes = new[] { Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)) };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 1, "Ep1"), RefEpisode(1, 2, "Ep2", DateOnly.FromDateTime(DateTime.Today.AddDays(30))))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().BeEmpty();
    }

    [Fact]
    public void ComputeInProgressShows_OrdersByLastWatchedDescending()
    {
        var shows = new[] { Show("show-1", "Older", referenceId: "ref-1"), Show("show-2", "Newer", referenceId: "ref-2") };
        var episodes = new[]
        {
            Episode("show-1", 1, 1, new DateOnly(2024, 1, 1)),
            Episode("show-2", 1, 1, new DateOnly(2024, 6, 1))
        };
        var references = new Dictionary<string, TvShowReferenceModel>
        {
            ["show-1"] = Reference(RefEpisode(1, 1, "Ep1"), RefEpisode(1, 2, "Ep2")),
            ["show-2"] = Reference(RefEpisode(1, 1, "Ep1"), RefEpisode(1, 2, "Ep2"))
        };

        var result = _service.ComputeInProgressShows(shows, episodes, references);

        result.Should().HaveCount(2);
        result[0].TvShowTitle.Should().Be("Newer");
        result[1].TvShowTitle.Should().Be("Older");
    }
}
