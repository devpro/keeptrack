namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// How stale something has to be for one sync pass to take it - the single declaration of the two windows,
/// read by both callers of the sync (<see cref="ReferenceSyncBackgroundService"/>'s periodic tick and the
/// admin's on-demand <c>POST /api/reference-data/sync-now</c>).
/// <para>
/// The windows are the *only* thing that differs between those two callers: an unforced "sync now" runs
/// exactly what the background pass would have run, so the values cannot be restated at the second call site
/// without the two silently drifting apart.
/// </para>
/// </summary>
/// <param name="References">Applied to <see cref="ReferenceSyncService.SyncStaleReferencesAsync"/>.</param>
/// <param name="Explore">Applied to <see cref="ExploreCatalogueRefreshService.RefreshAsync"/>.</param>
public readonly record struct ReferenceSyncWindows(TimeSpan References, TimeSpan Explore)
{
    /// <summary>
    /// What the 24h background tick uses.
    /// <para>
    /// The Explore window is much longer than the reference one because it is a different kind of data:
    /// "which titles are the best rated" barely moves week to week, and a rebuild walks a provider's list from
    /// the top rather than re-checking documents that individually changed. Riding the same tick (and the same
    /// lease) rather than adding a second scheduled workload keeps the no-external-scheduler rationale intact -
    /// the tick just usually finds the rankings still fresh and skips them.
    /// </para>
    /// </summary>
    public static readonly ReferenceSyncWindows Periodic = new(TimeSpan.FromDays(3), TimeSpan.FromDays(7));

    /// <summary>
    /// Re-check everything, however recently it was last enriched - what the admin's "force" option asks for.
    /// </summary>
    public static readonly ReferenceSyncWindows Forced = new(TimeSpan.Zero, TimeSpan.Zero);

    /// <summary>
    /// <see cref="Forced"/> when <paramref name="force"/>, otherwise the very same <see cref="Periodic"/>
    /// windows the background pass runs on.
    /// </summary>
    public static ReferenceSyncWindows For(bool force) => force ? Forced : Periodic;
}
