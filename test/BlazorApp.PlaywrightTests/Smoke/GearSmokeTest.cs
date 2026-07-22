using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Add/edit/delete coverage for the new Gear type - see <see cref="CollectibleSmokeTest"/> for why opening
/// the detail page (not just building/unit-testing) is the point of this test.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class GearSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddEditAndDelete_GearThroughTheList()
    {
        SkipIfReadOnly();

        var title = $"E2e Smoke Gear {Guid.NewGuid():N}";
        const string imageUrl = "https://picsum.photos/seed/e2e-gear/600/300";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenGearAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", title);
        await list.SaveNewAsync();

        var detail = new GearDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        list = await detail.OpenGearAsync();
        // ItemImageShape="wide" (same as VideoGames.razor) - a plain default-portrait thumb was the
        // reported regression, so this pins the actual rendered shape, not just that an image exists.
        await Assertions.Expect(list.Row(title).Locator(".kt-item-thumb.wide img")).ToHaveAttributeAsync("src", imageUrl);

        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
