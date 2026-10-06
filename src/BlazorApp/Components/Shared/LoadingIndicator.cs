namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Gates a page's loading-spinner flag behind a short delay.
/// Blazor renders once before the first await and once after, which flashes the spinner for a frame even when the load is fast.
/// An in-circuit navigation is usually faster than <see cref="s_delay"/>, so the spinner appears only when the load is still running after it.
/// </summary>
public static class LoadingIndicator
{
    private static readonly TimeSpan s_delay = TimeSpan.FromMilliseconds(1000);

    public static async Task RunAsync(Task load, Action<bool> setLoading, Action stateHasChanged)
    {
        if (await Task.WhenAny(load, Task.Delay(s_delay)) != load)
        {
            setLoading(true);
            stateHasChanged();
        }

        await load;
    }
}
