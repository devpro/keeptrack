namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shows a freshly created item's reference link once the server's background resolution lands.
/// </summary>
/// <remarks>
/// <para>
/// Creating an item returns once it is stored, and its reference resolves afterwards on a detached task (<c>DataCrudControllerBase.OnCreatedAsync</c>), so a slow provider never holds up a create or a bulk import.
/// The Add form navigates straight to the detail page, whose first read can precede the link, so a matched item would render unmatched until something re-read it.
/// </para>
/// <para>
/// It polls the item, not the provider, and gives up after a few reads, since an item with no match settling as unmatched is a real answer.
/// It stops once the page has changes of its own, since a re-read replaces the page's whole model and would undo them (see <c>ReferenceLinkedDetailPageBase</c>).
/// </para>
/// </remarks>
public static class PendingReferenceLink
{
    /// <summary>With <see cref="MaxAttempts"/>, how long to keep watching before accepting that there is no match to show.</summary>
    /// <remarks>
    /// Comfortably past a normal resolve (two IGDB searches plus a details call), and short of the provider clients' 30s resilience ceiling, where the answer would be "the provider is down" rather than "no match".
    /// </remarks>
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1.5);

    private const int MaxAttempts = 6;

    /// <summary>
    /// Re-reads the item until it reports a reference link, then renders it.
    /// </summary>
    /// <param name="isLinked">Whether the page's item is linked, checked before the first wait, so an already-linked item costs nothing.</param>
    /// <param name="reloadAsync">Re-reads the item, the same fetch the page does on load.</param>
    /// <param name="renderAsync">The page's <c>InvokeAsync(StateHasChanged)</c>, since the poll runs off the render loop and may not touch component state directly.</param>
    /// <param name="isUnedited">
    /// Whether the page still holds exactly what it loaded.
    /// False once the user has saved anything, when a re-read would discard their change rather than reveal a link.
    /// </param>
    public static async Task WatchAsync(Func<bool> isLinked, Func<Task> reloadAsync, Func<Task> renderAsync, Func<bool> isUnedited)
    {
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            if (isLinked() || !isUnedited()) return;

            await Task.Delay(PollInterval);
            // Re-checked after the wait as well as before it, since a save can land between the two, while this poll's own read is in flight.
            if (!isUnedited()) return;
            try
            {
                await reloadAsync();
            }
            catch
            {
                // A navigation away mid-poll disposes the circuit's scoped HttpClient, and there is nothing to report to a user who has left.
                return;
            }

            await renderAsync();
        }
    }
}
