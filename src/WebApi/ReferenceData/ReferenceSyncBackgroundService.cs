using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Keeps reference data fresh without any external scheduler (no Kubernetes CronJob, no separate worker
/// process): a plain in-process <see cref="PeriodicTimer"/> loop, ticking on its own DI scope since the
/// hosted service itself is a singleton. An admin can also force an immediate run via
/// <c>POST /api/reference-data/sync-now</c> (see <see cref="ReferenceDataAdminController"/>), which calls
/// the same <see cref="ReferenceSyncService"/> - this loop only decides *when* to run it, not *how*.
/// </summary>
public class ReferenceSyncBackgroundService(
    IServiceScopeFactory scopeFactory, IConfiguration configuration, ILogger<ReferenceSyncBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(24);
    private static readonly TimeSpan StaleAfter = TimeSpan.FromDays(3);

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
                var syncService = scope.ServiceProvider.GetRequiredService<ReferenceSyncService>();
                var result = await syncService.SyncStaleReferencesAsync(StaleAfter, stoppingToken);
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
