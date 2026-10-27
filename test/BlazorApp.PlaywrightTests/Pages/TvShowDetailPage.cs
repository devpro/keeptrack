using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public sealed class TvShowDetailPage(IPage page) : ReferenceableDetailPageBase(page)
{
    /// <summary>
    /// The episode checklist renders once the show is linked, grouped by season with the lowest selected, so the first row is season 1, episode 1 for a normally numbered show.
    /// </summary>
    private ILocator FirstEpisodeCheckbox => Page.Locator(".kt-episode-row").First.Locator("input[type=checkbox]");

    public async Task SetStateAsync(string state)
        => await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = state, Exact = true }).ClickAsync();

    public async Task MarkFirstEpisodeWatchedAsync()
    {
        await Assertions.Expect(FirstEpisodeCheckbox).ToBeVisibleAsync();
        await FirstEpisodeCheckbox.CheckAsync();
    }
}
