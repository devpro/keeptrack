using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Jobs;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps reference data fresh with no external scheduler: an in-process <see cref="PeriodicTimer"/> loop, each tick on its own DI scope, since the hosted service is a singleton.
/// An admin can run it at once through <c>POST /api/reference-data/sync-now</c>, which calls the same <see cref="ReferenceSyncService"/>, so this loop only decides when.
/// Every replica runs the loop, but only the one winning the <see cref="ILeaseRepository"/> lease syncs,
/// so scaling out neither multiplies provider traffic nor races on the same documents.
/// </summary>
public class ReferenceSyncBackgroundService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration, ILogger<ReferenceSyncBackgroundService> logger) : BackgroundService
{
    private const string LeaseName = "reference-sync";

    /// <summary>
    /// Owner id of a periodic job record, only satisfying <see cref="JobStore{TStage,TResult}.CreateAsync"/>, since the admin "Recent jobs" panel ignores owners.
    /// Recording the job shows the periodic pass in that panel, and not only in logs.
    /// </summary>
    private const string SystemOwnerId = "system";

    private static readonly TimeSpan s_interval = TimeSpan.FromHours(24);

    // declared once in ReferenceSyncWindows, since an unforced "sync now" runs this same pass
    private static readonly ReferenceSyncWindows s_windows = ReferenceSyncWindows.Periodic;

    // longer than any sync and much shorter than the 24h tick: a replica dying with the lease delays the next pass by this much,
    // and a new pod finding the old pod's lease live yields until its next tick
    private static readonly TimeSpan s_leaseDuration = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(s_interval);
        do
        {
            // checked on every tick, so the test host's override to false applies whenever it is merged into the configuration
            if (!new AppConfiguration(configuration).IsReferenceSyncEnabled) continue;

            Guid? jobId = null;
            try
            {
                using var scope = scopeFactory.CreateScope();

                // MachineName is the Kubernetes pod name: unique per replica, stable across ticks
                var lease = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
                if (!await lease.TryAcquireAsync(LeaseName, Environment.MachineName, s_leaseDuration))
                {
                    logger.LogInformation("Reference sync skipped: another instance holds the '{LeaseName}' lease.", LeaseName);
                    continue;
                }

                // recorded like an admin's "sync now", so the periodic pass appears in the admin "Recent jobs" panel
                var jobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();
                jobId = await jobStore.CreateAsync(SystemOwnerId, ReferenceSyncStage.SyncingTvShows);

                var syncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
                var result = await syncService.SyncStaleReferencesAsync(s_windows.References, fullFetch: s_windows.FullFetch, cancellationToken: stoppingToken);

                // the Explore rankings ride the same tick on their own longer window (see ReferenceSyncWindows.Periodic)
                var exploreRefreshService = scope.ServiceProvider.GetRequiredService<ExploreCatalogueRefreshService>();
                result.ApplyExploreRefresh(await exploreRefreshService.RefreshAsync(s_windows.Explore, stoppingToken));

                await jobStore.CompleteAsync(jobId.Value, ReferenceSyncStage.Completed, result);
                // every synced domain is reported, or a pass refreshing books, games or albums would read as having done nothing
                logger.LogInformation(
                    "Reference sync: {TvShowsChecked} TV show(s) checked ({TvShowsUpdated} updated), {MoviesChecked} movie(s) checked ({MoviesUpdated} updated), {BooksChecked} book(s) checked ({BooksUpdated} updated), {VideoGamesChecked} video game(s) checked ({VideoGamesUpdated} updated), {AlbumsChecked} album(s) checked ({AlbumsUpdated} updated), {FinishedShowsReopened} finished show(s) reopened, {ExploreRankingsRefreshed} Explore ranking(s) refreshed.",
                    result.TvShowsChecked, result.TvShowsUpdated, result.MoviesChecked, result.MoviesUpdated,
                    result.BooksChecked, result.BooksUpdated, result.VideoGamesChecked, result.VideoGamesUpdated,
                    result.AlbumsChecked, result.AlbumsUpdated, result.FinishedShowsReopened, result.ExploreRankingsRefreshed);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Reference sync run failed.");

                // the scope that created the job is disposed by now, so the failure is reported on a new scope
                if (jobId is not null)
                {
                    using var failureScope = scopeFactory.CreateScope();
                    var jobStore = failureScope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();
                    await jobStore.FailAsync(jobId.Value, ReferenceSyncStage.Failed, ex.Message);
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
