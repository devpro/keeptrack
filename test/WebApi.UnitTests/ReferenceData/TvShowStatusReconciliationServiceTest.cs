using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

[Trait("Category", "UnitTests")]
public class TvShowStatusReconciliationServiceTest
{
    private readonly Mock<ITvShowRepository> _tvShowRepository = new();
    private readonly Mock<IEpisodeRepository> _episodeRepository = new();
    private readonly Mock<ITvShowReferenceRepository> _tvShowReferenceRepository = new();

    private TvShowStatusReconciliationService CreateService() => new(
        _tvShowRepository.Object, _episodeRepository.Object, _tvShowReferenceRepository.Object,
        NullLogger<TvShowStatusReconciliationService>.Instance);

    private static TvShowModel FinishedShow(string id, string ownerId = "owner", string referenceId = "ref-1") =>
        new()
        {
            Id = id,
            OwnerId = ownerId,
            Title = "Dark",
            State = TvShowStatus.Finished,
            ReferenceId = referenceId
        };

    private static EpisodeModel Episode(string showId, int season, int episode, string ownerId = "owner") =>
        new() { OwnerId = ownerId, TvShowId = showId, SeasonNumber = season, EpisodeNumber = episode };

    private static ReferenceEpisodeModel RefEpisode(int season, int episode, DateOnly? airDate = null) =>
        new() { SeasonNumber = season, EpisodeNumber = episode, Title = $"S{season}E{episode}", AirDate = airDate };

    private static TvShowReferenceModel Reference(string id, params ReferenceEpisodeModel[] episodes) => new()
    {
        Id = id,
        Title = "Dark",
        TitleNormalized = "dark",
        ExternalIds = new Dictionary<string, string>(),
        Episodes = [.. episodes]
    };

    private void Setup(IReadOnlyList<TvShowModel> shows, IReadOnlyList<EpisodeModel> episodes, params TvShowReferenceModel[] references)
    {
        _tvShowRepository.Setup(r => r.FindFinishedLinkedShowsAsync()).ReturnsAsync(shows);
        _tvShowReferenceRepository.Setup(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>()))
            .ReturnsAsync(references.ToList());
        _episodeRepository.Setup(r => r.FindByShowIdsAsync(It.IsAny<string>(), It.IsAny<IReadOnlyCollection<string>>()))
            .ReturnsAsync((string ownerId, IReadOnlyCollection<string> ids) =>
                episodes.Where(e => e.OwnerId == ownerId && ids.Contains(e.TvShowId)).ToList());
    }

    [Fact]
    public async Task Reopens_FinishedShow_WhenReferenceHasAnAiredEpisodeAfterTheLastWatched()
    {
        Setup(
            [FinishedShow("show-1")],
            [Episode("show-1", 1, 10)],
            Reference("ref-1", RefEpisode(1, 10), RefEpisode(2, 1, new DateOnly(2024, 1, 1))));
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(1);
        _tvShowRepository.Verify(r => r.UpdateAsync(
            "show-1", It.Is<TvShowModel>(s => s.State == TvShowStatus.Current), "owner"), Times.Once);
    }

    [Fact]
    public async Task LeavesShowAlone_WhenAlreadyCaughtUpWithTheReferenceGuide()
    {
        Setup(
            [FinishedShow("show-1")],
            [Episode("show-1", 2, 1)],
            Reference("ref-1", RefEpisode(1, 10), RefEpisode(2, 1)));
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(0);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task LeavesShowAlone_WhenTheOnlyNewerEpisodeHasNotAiredYet()
    {
        Setup(
            [FinishedShow("show-1")],
            [Episode("show-1", 1, 10)],
            Reference("ref-1", RefEpisode(1, 10), RefEpisode(2, 1, DateOnly.FromDateTime(DateTime.Today.AddDays(30)))));
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(0);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task LeavesShowAlone_WhenItHasNoRecordedEpisodes()
    {
        // no last-watched episode to compare against - can't tell whether a newer one exists, so don't guess.
        Setup(
            [FinishedShow("show-1")],
            [],
            Reference("ref-1", RefEpisode(1, 1, new DateOnly(2024, 1, 1))));
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(0);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task LeavesShowAlone_WhenItsReferenceDocumentIsMissing()
    {
        Setup(
            [FinishedShow("show-1", referenceId: "ref-1")],
            [Episode("show-1", 1, 10)]);
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(0);
        _tvShowRepository.Verify(r => r.UpdateAsync(It.IsAny<string>(), It.IsAny<TvShowModel>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task ReconcilesEachTenantsOwnEpisodes_WhenTwoTenantsShareAReference()
    {
        // same reference, but each tenant's last-watched differs: only the tenant behind on the guide reopens.
        Setup(
            [FinishedShow("show-a", "owner-a"), FinishedShow("show-b", "owner-b")],
            [Episode("show-a", 1, 10, "owner-a"), Episode("show-b", 2, 1, "owner-b")],
            Reference("ref-1", RefEpisode(1, 10), RefEpisode(2, 1, new DateOnly(2024, 1, 1))));
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(1);
        _tvShowRepository.Verify(r => r.UpdateAsync("show-a", It.IsAny<TvShowModel>(), "owner-a"), Times.Once);
        _tvShowRepository.Verify(r => r.UpdateAsync("show-b", It.IsAny<TvShowModel>(), "owner-b"), Times.Never);
    }

    [Fact]
    public async Task ContinuesPastAFailedShow_AndStillProcessesTheRest()
    {
        Setup(
            [FinishedShow("bad", "owner"), FinishedShow("good", "owner")],
            [Episode("bad", 1, 1), Episode("good", 1, 1)],
            Reference("ref-1", RefEpisode(1, 1), RefEpisode(1, 2, new DateOnly(2024, 1, 1))));
        _tvShowRepository.Setup(r => r.UpdateAsync("bad", It.IsAny<TvShowModel>(), It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("Simulated write failure."));
        _tvShowRepository.Setup(r => r.UpdateAsync("good", It.IsAny<TvShowModel>(), It.IsAny<string>())).ReturnsAsync(1);
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(1);
        _tvShowRepository.Verify(r => r.UpdateAsync("good", It.IsAny<TvShowModel>(), "owner"), Times.Once);
    }

    [Fact]
    public async Task DoesNothing_WhenNoFinishedLinkedShowsExist()
    {
        Setup([], []);
        var service = CreateService();

        var reopened = await service.ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().Be(0);
        _tvShowReferenceRepository.Verify(r => r.FindByIdsAsync(It.IsAny<IReadOnlyCollection<string>>()), Times.Never);
    }
}
