using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// Only asserted to load in phase 2 - meaningful content assertions need reference-linked, partially-watched
/// seed data, deferred to a later phase per the e2e plan.
/// </summary>
public class WishlistPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new() { Name = "Wishlist", Level = 1 })).ToBeVisibleAsync();
        await Assertions.Expect(Page.Locator(".kt-spinner")).ToBeHiddenAsync();
    }
}
