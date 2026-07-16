using Keeptrack.Domain.Repositories;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps reference data fresh without any external scheduler (no Kubernetes CronJob, no separate worker
/// process): a plain in-process <see cref="PeriodicTimer"/> loop, ticking on its own DI scope since the
/// hosted service itself is a singleton. An admin can also force an immediate run via
/// <c>POST /api/reference-data/sync-now</c> (see <see cref="ReferenceDataAdminController"/>), which calls
/// the same <see cref="ReferenceSyncService"/> - this loop only decides *when* to run it, not *how*.
/// With multiple WebApi replicas, every replica runs this loop but only the one that wins the
/// <see cref="ILeaseRepository"/> lease actually syncs, so a scaled-out deployment doesn't multiply
/// provider traffic or race concurrent enrichments of the same documents - and no dedicated
/// "sync workload" manifest is needed, keeping the original no-external-scheduler rationale intact.
/// </summary>
public class ReferenceSyncBackgroundService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration, ILogger<ReferenceSyncBackgroundService> logger) : BackgroundService
{
    private const string LeaseName = "reference-sync";

    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromDays(3);

    // comfortably longer than any sync run, much shorter than the 24h tick: a replica that dies holding
    // the lease only delays the next successful pass by this long, and a rolling deploy's brand-new pod
    // (whose startup pass finds the previous pod's lease still live) just yields until its next tick.
    private static readonly TimeSpan LeaseDuration = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        do
        {
            // checked on every tick (rather than once at startup) so the integration test host - which
            // overrides Features:IsReferenceSyncEnabled to false to keep tests from firing real TMDB calls
            // against shared test data - never runs this, regardless of when that override is merged in
            // relative to this service's own construction.
            if (!new AppConfiguration(configuration).IsReferenceSyncEnabled) continue;

            try
            {
                using var scope = scopeFactory.CreateScope();

                // MachineName is the pod name under Kubernetes: unique per replica, stable across ticks
                var lease = scope.ServiceProvider.GetRequiredService<ILeaseRepository>();
                if (!await lease.TryAcquireAsync(LeaseName, Environment.MachineName, LeaseDuration))
                {
                    logger.LogInformation("Reference sync skipped: another instance holds the '{LeaseName}' lease.", LeaseName);
                    continue;
                }

                var syncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
                var result = await syncService.SyncStaleReferencesAsync(StaleAfter, cancellationToken: stoppingToken);
                logger.LogInformation(
                    "Reference sync: {TvShowsChecked} TV show(s) checked ({TvShowsUpdated} updated), {MoviesChecked} movie(s) checked ({MoviesUpdated} updated).",
                    result.TvShowsChecked, result.TvShowsUpdated, result.MoviesChecked, result.MoviesUpdated);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Reference sync run failed.");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
