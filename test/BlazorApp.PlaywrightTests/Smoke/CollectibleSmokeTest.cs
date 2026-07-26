using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Add/edit/delete coverage for the new Collectible type, same shape as <see cref="CarSmokeTest"/>.
/// Opening the detail page here is exactly the flow that regressed once already: the new type's API
/// client was added to the codebase but never registered in BlazorApp's DI container
/// (AddWebApiHttpClient), so navigating to the list and opening an item threw InvalidOperationException
/// at render time - a bug the build and every unit test missed, and only a real browser click surfaces.
/// This also covers the cover image round trip (fill the URL, see the detail banner and the list's wide
/// thumbnail both pick it up) - the other thing that shipped wrong on the first two attempts.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class CollectibleSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddEditAndDelete_CollectibleThroughTheList()
    {
        SkipIfReadOnly();

        var title = $"E2e Smoke Collectible {Guid.NewGuid():N}";
        const string imageUrl = "https://picsum.photos/seed/e2e-collectible/600/300";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenCollectiblesAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", title);
        await list.SaveNewAsync();

        var detail = new CollectibleDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        list = await detail.OpenCollectiblesAsync();
        // ItemImageShape="wide" (same as VideoGames.razor) - a plain default-portrait thumb was the
        // reported regression, so this pins the actual rendered shape, not just that an image exists.
        await Assertions.Expect(list.Row(title).Locator(".kt-item-thumb.wide img")).ToHaveAttributeAsync("src", imageUrl);

        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
