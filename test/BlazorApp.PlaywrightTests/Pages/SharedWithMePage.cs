using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The recipient's "Shared with me" list (<c>/account/manage/shared-with-me</c>): the people who shared a
/// collection with the caller. Selecting one opens their <see cref="SharedCollectionViewPage"/>.
/// </summary>
public class SharedWithMePage(IPage page) : PageBase(page)
{
    public async Task<SharedWithMePage> OpenAsync()
    {
        await Page.GotoAsync("/account/manage/shared-with-me");
        await WaitForReadyAsync();
        return this;
    }

    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Shared with me", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }

    /// <summary>Any sharer row - the list shows one card per person who shared a collection with the caller.</summary>
    public ILocator PersonRow => Page.Locator(".kt-item-row");

    /// <summary>
    /// Opens a specific shared collection by id. The list rows show only the sharer's display name (identical
    /// for every self-share grant), so a test that created its grant to its own email navigates by the grant id
    /// it read back from the API rather than by an ambiguous row match.
    /// </summary>
    public async Task<SharedCollectionViewPage> OpenCollectionByIdAsync(string shareId)
    {
        await Page.GotoAsync($"/account/manage/shared/{shareId}");
        var collection = new SharedCollectionViewPage(Page);
        await collection.WaitForReadyAsync();
        return collection;
    }
}
