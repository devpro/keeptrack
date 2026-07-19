using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Proves the video game platform editor's draft-card + trash-icon flow end-to-end - the same
/// draft-until-Save and confirm-before-remove UX as <see cref="OwnershipSmokeTest"/>'s owned-versions
/// flow, applied here to <c>VideoGamePlatformDto</c>'s own field set (state and completion, on top of
/// the price/vendor/acquired-date/reference fields it now shares with every other media type's copies).
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class VideoGamePlatformSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddingAndRemovingAPlatform_DrivesTheDraftAndConfirmFlow()
    {
        SkipIfReadOnly();

        var title = $"E2e Platform Game {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenVideoGamesAsync();
        await list.ClickAddAsync();
        await list.FillByPlaceholderAsync("Title", title);
        await list.SaveNewAsync();

        var detail = new VideoGameDetailPage(Page);
        await detail.WaitForReadyAsync();

        // a new platform is a draft until its Save button - cancelling discards it
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add platform" }).ClickAsync();
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Cancel" }).ClickAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add platform" })).ToBeVisibleAsync();

        // add a platform (defaults to Physical) and save the draft - an untouched platform has no
        // details to lose, so removing it needs no confirmation
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add platform" }).ClickAsync();
        await Page.Locator("select.form-select-sm").SelectOptionAsync("PC");
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Save", Exact = true }).ClickAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "PC" })).ToBeVisibleAsync();

        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Remove this platform" }).ClickAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "PC" })).Not.ToBeVisibleAsync();

        // re-add and set a state this time - the platform now has a detail to lose, so removing it asks first
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add platform" }).ClickAsync();
        await Page.Locator("select.form-select-sm").SelectOptionAsync("PC");
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Save", Exact = true }).ClickAsync();
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Current" }).ClickAsync();

        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Remove this platform" }).ClickAsync();
        await Assertions.Expect(Page.GetByText("Remove this platform?")).ToBeVisibleAsync();
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Remove", Exact = true }).ClickAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "PC" })).Not.ToBeVisibleAsync();

        list = await detail.OpenVideoGamesAsync();
        await list.DeleteAsync(title);
    }
}
