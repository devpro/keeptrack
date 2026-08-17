namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shows a freshly created item's reference link once the server's background resolution lands.
/// </summary>
/// <remarks>
/// <para>
/// Creating an item returns as soon as it is stored, and its reference is resolved afterwards on a detached background task (<c>DataCrudControllerBase.OnCreatedAsync</c>) - deliberately, because that task makes a chain of provider calls and a slow or failing provider must never hold up a create, still less a bulk import.
/// The consequence is a race the user always loses: the Add form navigates straight to the detail page, which fetches the item within milliseconds while the resolution is still a second or three away, and then never reads it again.
/// So a game that matched perfectly renders as unmatched, and stays that way until something else causes a re-read.
/// </para>
/// <para>
/// Reported repeatedly and each time as a matching bug - "I create Resident Evil 2 with year 2019, it doesn't match, but if I click on refresh it matches".
/// The click was never fixing anything: it re-read an item the server had already linked.
/// That is also why it looked intermittent and provider-dependent, since whether the page won or lost the race depended on how quickly IGDB answered.
/// </para>
/// <para>
/// This polls the item itself rather than the provider, so it costs a handful of cheap reads and only for an item that is actually unlinked.
/// It gives up rather than waiting forever: an item that legitimately has no match must settle as unmatched, which is a real answer and not a spinner.
/// </para>
/// <para>
/// It also gives up the moment the page has changes of its own, and that half is not a nicety.
/// A re-read replaces the page's whole model, so a poll issued before a save and answered after it puts the pre-save document back on screen <b>and</b> back into the model - the user's edit disappears, and the next save writes the resurrected version back to the server.
/// Observed on a just-created game whose platform was removed inside the polling window: the platform reappeared, with everything that had been set on it.
/// Nothing is lost by stopping, either: someone editing the item is no longer waiting to see whether a link lands, and the link still shows on the next load.
/// </para>
/// </remarks>
public static class PendingReferenceLink
{
    /// <summary>How long to keep watching before accepting that there is no match to show.</summary>
    /// <remarks>
    /// Comfortably past a normal resolve (two IGDB searches plus a details call) without approaching the provider clients' own 30s resilience ceiling, where the answer would be "the provider is down" rather than "no match".
    /// </remarks>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1.5);

    private const int MaxAttempts = 6;

    /// <summary>
    /// Re-reads the item until it reports a reference link, then renders it.
    /// </summary>
    /// <param name="isLinked">
    /// Whether the item currently held by the page is linked - checked before the first wait, so an already-linked item costs nothing.</param>
    /// <param name="reloadAsync">
    /// Re-reads the item; the same fetch the page does on load.</param>
    /// <param name="renderAsync">
    /// The page's <c>InvokeAsync(StateHasChanged)</c> - the poll runs off the render loop, so it may not touch component state directly.</param>
    /// <param name="isUnedited">
    /// Whether the page still holds exactly what it loaded - false once the user has saved anything, at which point a re-read would discard their change rather than reveal a link.</param>
    public static async Task WatchAsync(Func<bool> isLinked, Func<Task> reloadAsync, Func<Task> renderAsync, Func<bool> isUnedited)
    {
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            if (isLinked() || !isUnedited()) return;

            await Task.Delay(PollInterval);
            // re-checked after the wait as well as before it: the whole window this guards against is the one *between* the two, where a save lands while this poll's own read is already in flight
            if (!isUnedited()) return;
            try
            {
                await reloadAsync();
            }
            catch
            {
                // A navigation away mid-poll disposes the circuit's scoped HttpClient under us, and there is nothing to report to a user who has already left.
                return;
            }

            await renderAsync();
        }
    }
}
