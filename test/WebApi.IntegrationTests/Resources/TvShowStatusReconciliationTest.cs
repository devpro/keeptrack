using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// <see cref="TvShowStatusReconciliationService"/> end to end against real MongoDB:
/// the finished-show query, the batched reference and episode reads, and the status write each pass alone, so this pins them together.
/// </summary>
public class TvShowStatusReconciliationTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    private static readonly int[] s_episodesPerSeason = [8, 6, 8, 8];

    [Fact]
    public async Task ReconcileFinishedShowsAsync_ReopensAFinishedShowWatchedUpToTheLastSeasonFinale_OnceANewSeasonHasAired()
    {
        using var scope = Factory.Services.CreateScope();
        var today = DateOnly.FromDateTime(DateTime.Today);
        var ownerId = $"owner-{Guid.NewGuid()}";
        var reference = await CreateReferenceAsync(scope, season => season == 4 ? today.AddDays(-13) : today.AddYears(season - 4));
        var show = await CreateShowAsync(scope, ownerId, TvShowStatus.Finished, reference.Id!);
        await RecordEpisodesUpToAsync(scope, ownerId, show.Id!, lastSeason: 3);

        var reopened = await scope.ServiceProvider.GetRequiredService<TvShowStatusReconciliationService>().ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        reopened.Should().BeGreaterThanOrEqualTo(1);
        var stored = await scope.ServiceProvider.GetRequiredService<ITvShowRepository>().FindOneAsync(show.Id!, ownerId, TestContext.Current.CancellationToken);
        stored!.State.Should().Be(TvShowStatus.Current);
    }

    [Fact]
    public async Task ReconcileFinishedShowsAsync_LeavesAFinishedShowAlone_WhileTheNewSeasonHasNotAired()
    {
        using var scope = Factory.Services.CreateScope();
        var today = DateOnly.FromDateTime(DateTime.Today);
        var ownerId = $"owner-{Guid.NewGuid()}";
        var reference = await CreateReferenceAsync(scope, season => season == 4 ? today.AddDays(30) : today.AddYears(season - 4));
        var show = await CreateShowAsync(scope, ownerId, TvShowStatus.Finished, reference.Id!);
        await RecordEpisodesUpToAsync(scope, ownerId, show.Id!, lastSeason: 3);

        await scope.ServiceProvider.GetRequiredService<TvShowStatusReconciliationService>().ReconcileFinishedShowsAsync(TestContext.Current.CancellationToken);

        var stored = await scope.ServiceProvider.GetRequiredService<ITvShowRepository>().FindOneAsync(show.Id!, ownerId, TestContext.Current.CancellationToken);
        stored!.State.Should().Be(TvShowStatus.Finished);
    }

    private async Task<TvShowReferenceModel> CreateReferenceAsync(IServiceScope scope, Func<int, DateOnly> airDateOfSeason)
    {
        var episodes = new List<ReferenceEpisodeModel>();
        for (var season = 1; season <= s_episodesPerSeason.Length; season++)
        {
            episodes.AddRange(Enumerable.Range(1, s_episodesPerSeason[season - 1]).Select(episode => new ReferenceEpisodeModel
            {
                SeasonNumber = season,
                EpisodeNumber = episode,
                Title = $"S{season}E{episode}",
                AirDate = airDateOfSeason(season)
            }));
        }

        var created = await scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>().UpsertAsync(new TvShowReferenceModel
        {
            Title = "The Diplomat",
            TitleNormalized = "the diplomat",
            Year = 2023,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            Episodes = episodes
        });
        TrackDocument("tvshow_reference", created.Id);
        return created;
    }

    private async Task<TvShowModel> CreateShowAsync(IServiceScope scope, string ownerId, TvShowStatus state, string referenceId)
    {
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowRepository>();
        var created = await repository.CreateAsync(new TvShowModel { OwnerId = ownerId, Title = "The Diplomat", Year = 2023, State = state, ReferenceId = referenceId });
        TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
        return created;
    }

    private async Task RecordEpisodesUpToAsync(IServiceScope scope, string ownerId, string showId, int lastSeason)
    {
        var repository = scope.ServiceProvider.GetRequiredService<IEpisodeRepository>();
        for (var season = 1; season <= lastSeason; season++)
        {
            for (var episode = 1; episode <= s_episodesPerSeason[season - 1]; episode++)
            {
                var created = await repository.CreateAsync(new EpisodeModel
                {
                    OwnerId = ownerId,
                    TvShowId = showId,
                    SeasonNumber = season,
                    EpisodeNumber = episode,
                    WatchedAt = DateOnly.FromDateTime(DateTime.Today)
                });
                TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
            }
        }
    }
}
