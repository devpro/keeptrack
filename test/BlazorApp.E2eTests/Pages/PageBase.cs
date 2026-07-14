using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.E2eTests.Pages;

/// <summary>
/// Shared plumbing for every page object. Blazor Server prerenders before the circuit connects, so "ready"
/// never means "the URL navigated" or network idle (the circuit's own websocket defeats that) - every page
/// in the app renders the same <c>.kt-spinner</c> while its <c>OnInitializedAsync</c> is still in flight (see
/// <c>InventoryList.razor</c>, <c>BookDetail.razor</c>, <c>WatchNextPage.razor</c>, <c>WishlistPage.razor</c>),
/// so waiting for it to become hidden is one interactive signal that works across every page, including ones
/// (like Home) that never render a spinner at all - <see cref="ILocatorAssertions.ToBeHiddenAsync"/> treats a
/// locator matching zero elements as already hidden.
/// </summary>
public abstract class PageBase(IPage page)
{
    protected IPage Page { get; } = page;

    protected static async Task WaitForLoadingToResolveAsync(IPage page)
        => await Assertions.Expect(page.Locator(".kt-spinner")).ToBeHiddenAsync();
}
