using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

public class WatchNextPage(IPage page) : PageBase(page)
{
    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Watch next", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>
    /// TV shows and movies share the <c>.kt-item-row</c> markup under the active tab, and the other tab's rows aren't in the DOM (a plain Blazor <c>@if</c>), so one locator serves both.
    /// </summary>
    public ILocator Card(string title) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = title });

    public ILocator CardBadge(string title) => Card(title).Locator(".kt-card-badge");

    public async Task OpenMoviesTabAsync() => await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Movies" }).ClickAsync();
}
