namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// How stale something must be for a sync pass to take it, declared once for both callers:
/// the periodic tick (<see cref="ReferenceSyncBackgroundService"/>) and the admin's <c>POST /api/reference-data/sync-now</c>.
/// <para>
/// The windows are the only difference between them: an unforced "sync now" runs exactly the background pass.
/// </para>
/// </summary>
/// <param name="References">Applied to <see cref="ReferenceSyncService.SyncStaleReferencesAsync"/>.</param>
/// <param name="Explore">Applied to <see cref="ExploreCatalogueRefreshService.RefreshAsync"/>.</param>
public readonly record struct ReferenceSyncWindows(TimeSpan References, TimeSpan Explore)
{
    /// <summary>
    /// The windows of the 24h background tick.
    /// <para>
    /// The Explore window is much longer, since the best-rated titles barely move week to week, and a rebuild walks a provider's list from the top.
    /// Riding the same tick and lease avoids a second scheduled workload, the tick usually finding the rankings fresh and skipping them.
    /// </para>
    /// </summary>
    public static readonly ReferenceSyncWindows Periodic = new(TimeSpan.FromDays(3), TimeSpan.FromDays(7));

    /// <summary>
    /// Checks everything again, however recently enriched, for the admin's "force" option.
    /// </summary>
    public static readonly ReferenceSyncWindows Forced = new(TimeSpan.Zero, TimeSpan.Zero);

    /// <summary>
    /// <see cref="Forced"/> when <paramref name="force"/>, else the <see cref="Periodic"/> windows of the background pass.
    /// </summary>
    public static ReferenceSyncWindows For(bool force) => force ? Forced : Periodic;
}
