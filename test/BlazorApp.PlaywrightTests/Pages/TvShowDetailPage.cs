using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class TvShowDetailPage(IPage page) : ReferenceableDetailPageBase(page, "TMDB")
{
    public override ILocator CoverImage => Page.GetByRole(AriaRole.Img, new() { NameRegex = new Regex("poster$") });

    /// <summary>
    /// The episode checklist only renders once the show is linked (<c>_reference is not null</c>), grouped
    /// by season with the lowest season selected by default - the first row is season 1 episode 1 for any
    /// normally-numbered show.
    /// </summary>
    private ILocator FirstEpisodeCheckbox => Page.Locator(".kt-episode-row").First.Locator("input[type=checkbox]");

    public async Task SetStateAsync(string state)
        => await Page.GetByRole(AriaRole.Button, new() { Name = state, Exact = true }).ClickAsync();

    public async Task MarkFirstEpisodeWatchedAsync()
    {
        await Assertions.Expect(FirstEpisodeCheckbox).ToBeVisibleAsync();
        await FirstEpisodeCheckbox.CheckAsync();
    }
}
