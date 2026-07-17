using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Proves the owned-versions flow end-to-end on a book (the editor is one shared component across
/// movie/TV show/book/album, so one type suffices): adding a version with purchase details persists,
/// the list row derives its "Owned" badge from it, and removing the version un-owns the item -
/// there is no stored owned flag anywhere in this flow.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class OwnershipSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddingAndRemovingAnOwnedVersion_DrivesTheOwnedState()
    {
        SkipIfReadOnly();

        var title = $"E2e Ownership Book {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenBooksAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", title);
        await list.FillAsync("author-input", "E2e Ownership Author");
        await list.SaveNewAsync();

        var detail = new BookDetailPage(Page);
        await detail.WaitForReadyAsync();

        // a new version is a draft until its Save button - cancelling discards it without owning the item
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add version" }).ClickAsync();
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Cancel" }).ClickAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add version" })).ToBeVisibleAsync();

        // add a version (defaults to Physical), fill in its purchase details, and save the draft
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add version" }).ClickAsync();
        await BookDetailPage.SetFieldAsync(Page.GetByTestId("version-price-input"), "12.50");
        await BookDetailPage.SetFieldAsync(Page.GetByTestId("version-acquired-input"), "2024-05-17");
        await BookDetailPage.SetFieldAsync(Page.GetByTestId("version-vendor-input"), "E2e Bookshop");
        await BookDetailPage.SetFieldAsync(Page.GetByTestId("version-reference-input"), "Paperback 2nd edition");
        await Page.GetByTestId("version-save-button").ClickAsync();

        // round-trip via the list: the row must show the derived Owned badge, and reopening the
        // detail page must show the persisted version fields
        list = await detail.OpenBooksAsync();
        await list.SearchAsync(title);
        await Assertions.Expect(list.Row(title).Locator(".kt-flag-badge", new LocatorLocatorOptions { HasText = "Owned" })).ToBeVisibleAsync();

        await list.OpenItemAsync(title);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByTestId("version-price-input")).ToHaveValueAsync("12.50");
        await Assertions.Expect(Page.GetByTestId("version-acquired-input")).ToHaveValueAsync("2024-05-17");
        await Assertions.Expect(Page.GetByTestId("version-vendor-input")).ToHaveValueAsync("E2e Bookshop");
        await Assertions.Expect(Page.GetByTestId("version-reference-input")).ToHaveValueAsync("Paperback 2nd edition");

        // removing the only version un-owns the item - the copy has details, so a confirmation is asked
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Remove this copy" }).ClickAsync();
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Remove", Exact = true }).ClickAsync();
        list = await detail.OpenBooksAsync();
        await list.SearchAsync(title);
        await Assertions.Expect(list.Row(title)).ToBeVisibleAsync();
        await Assertions.Expect(list.Row(title).Locator(".kt-flag-badge", new LocatorLocatorOptions { HasText = "Owned" })).Not.ToBeVisibleAsync();

        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
