using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// One owner's shared collection, read-only (<c>/account/manage/shared/{shareId}</c>): a tab per shared
/// category. Media tabs list items (with an "In collection" badge for what the caller already owns); personal
/// tabs list items that each open a read-only detail page.
/// </summary>
public class SharedCollectionViewPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
        await Assertions.Expect(Page.Locator(".kt-tabs")).ToBeVisibleAsync();
    }

    public async Task SelectTabAsync(string label)
        => await Page.Locator(".kt-tab", new PageLocatorOptions { HasText = label }).ClickAsync();

    /// <summary>A list row (media or personal) containing the given item title.</summary>
    public ILocator Row(string itemTitle) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = itemTitle });

    /// <summary>The "In collection" badge shown for a shared media item the caller already owns.</summary>
    public ILocator InCollectionBadge(string itemTitle) => Row(itemTitle).GetByText("In collection");

    /// <summary>Opens a personal item's read-only detail page (the personal rows are links).</summary>
    public async Task<CarDetailPage> OpenCarAsync(string name)
    {
        await Row(name).ClickAsync();
        var detail = new CarDetailPage(Page);
        await detail.WaitForReadyAsync();
        return detail;
    }
}
