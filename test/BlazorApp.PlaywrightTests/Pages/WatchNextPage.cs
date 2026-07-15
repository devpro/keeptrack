using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class WatchNextPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = "Watch next", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>
    /// TV shows and movies share the same <c>.kt-item-row</c> markup, just under whichever tab is currently
    /// active - the other tab's rows aren't in the DOM at all (a plain Blazor <c>@if</c>), so there's no
    /// ambiguity risk in reusing one locator for both.
    /// </summary>
    public ILocator Card(string title) => Page.Locator(".kt-item-row", new() { HasText = title });

    public ILocator CardBadge(string title) => Card(title).Locator(".kt-card-badge");

    public async Task OpenMoviesTabAsync() => await Page.GetByRole(AriaRole.Button, new() { Name = "Movies" }).ClickAsync();
}
