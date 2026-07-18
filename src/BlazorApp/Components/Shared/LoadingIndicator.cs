namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Gates a page's loading-spinner flag behind a short delay. Blazor's async lifecycle rendering
/// (render once before the first await, once after) flashes the spinner for a single frame even
/// when the load is fast - the common case for an in-circuit navigation between two already-
/// connected pages, which is usually faster than <see cref="Delay"/>. The spinner only actually
/// appears when the load is still running once that delay elapses.
/// </summary>
public static class LoadingIndicator
{
    private static readonly TimeSpan Delay = TimeSpan.FromMilliseconds(200);

    public static async Task RunAsync(Task load, Action<bool> setLoading, Action stateHasChanged)
    {
        if (await Task.WhenAny(load, Task.Delay(Delay)) != load)
        {
            setLoading(true);
            stateHasChanged();
        }

        await load;
    }
}
