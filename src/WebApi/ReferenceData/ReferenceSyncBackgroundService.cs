using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Jobs;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps reference data fresh without any external scheduler (no Kubernetes CronJob, no separate worker process):
/// a plain in-process <see cref="PeriodicTimer"/> loop, ticking on its own DI scope since the hosted service itself is a singleton.
/// An admin can also force an immediate run via <c>POST /api/reference-data/sync-now</c> (see <see cref="ReferenceDataAdminController"/>),
/// which calls the same <see cref="ReferenceSyncService"/> - this loop only decides *when* to run it, not *how*.
/// With multiple WebApi replicas, every replica runs this loop but only the one that wins the <see cref="ILeaseRepository"/> lease actually syncs,
/// so a scaled-out deployment doesn't multiply provider traffic or race concurrent enrichments of the same documents -
/// and no dedicated "sync workload" manifest is needed, keeping the original no-external-scheduler rationale intact.
/// </summary>
public class ReferenceSyncBackgroundService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration, ILogger<ReferenceSyncBackgroundService> logger) : BackgroundService
{
    private const string LeaseName = "reference-sync";

    /// <summary>
    /// Placeholder owner id for a periodic (not admin-triggered) job record - <see cref="Controllers.SystemStatusController"/>'s
    /// "Recent jobs" panel doesn't filter or display by owner (it's an unscoped admin diagnostic read), so this
    /// exists only to satisfy <see cref="JobStore{TStage,TResult}.CreateAsync"/>'s signature. Without recording a
    /// job here, the periodic run was invisible in that panel (which only ever showed admin "sync now" jobs),
    /// even though the lease/logs proved it was running - the missing job history was mistaken for the sync not running at all.
    /// </summary>
    private const string SystemOwnerId = "system";

    private static readonly TimeSpan s_interval = TimeSpan.FromHours(24);
    private static readonly TimeSpan s_staleAfter = TimeSpan.FromDays(3);

    // comfortably longer than any sync run, much shorter than the 24h tick:
    // a replica that dies holding the lease only delays the next successful pass by this long,
    // and a rolling deploy's brand-new pod (whose startup pass finds the previous pod's lease still live) just yields until its next tick.
    private static readonly TimeSpan s_leaseDuration = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(s_interval);
        do
        {
            // checked on every tick (rather than once at startup) so the integration test host -
            // which overrides Features:IsReferenceSyncEnabled to false to keep tests from firing real TMDB calls against shared test data -
            // never runs this, regardless of when that override is merged in relative to this service's own construction.
            if (!new AppConfiguration(configuration).IsReferenceSyncEnabled) continue;

            Guid? jobId = null;
            try
            {
                using var scope = scopeFactory.CreateScope();

                // MachineName is the pod name under Kubernetes: unique per replica, stable across ticks
                var lease = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
                if (!await lease.TryAcquireAsync(LeaseName, Environment.MachineName, s_leaseDuration))
                {
                    logger.LogInformation("Reference sync skipped: another instance holds the '{LeaseName}' lease.", LeaseName);
                    continue;
                }

                // recorded in the same background_job collection as the admin's manual "sync now", so a
                // periodic pass is visible in the admin system-status page's "Recent jobs" panel too, not
                // just in logs and the lease's own expiry timestamp
                var jobStore = scope.ServiceProvider.GetRequiredService<JobStore<ReferenceSyncStage, ReferenceSyncResultDto>>();
                jobId = await jobStore.CreateAsync(SystemOwnerId, ReferenceSyncStage.SyncingTvShows);

                var syncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
                var result = await syncService.SyncStaleReferencesAsync(s_staleAfter, cancellationToken: stoppingToken);
                await jobStore.CompleteAsync(jobId.Value, ReferenceSyncStage.Completed, result);
                logger.LogInformation(
                    "Reference sync: {TvShowsChecked} TV show(s) checked ({TvShowsUpdated} updated), {MoviesChecked} movie(s) checked ({MoviesUpdated} updated).",
                    result.TvShowsChecked, result.TvShowsUpdated, result.MoviesChecked, result.MoviesUpdated);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Reference sync run failed.");

                // the scope that created the job was already disposed by the time we get here (it's scoped
                // to the try block above), so failure reporting needs its own fresh scope - same reasoning
                // as ReferenceDataAdminController.RunSyncJobAsync's own scope
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
