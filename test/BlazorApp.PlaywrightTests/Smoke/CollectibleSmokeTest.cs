using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Add, edit and delete coverage for collectibles, the shape of <see cref="CarSmokeTest"/>.
/// Opening the detail page proves the API client is registered in BlazorApp's DI container (AddWebApiHttpClient), which the build and unit tests can't, an unregistered client throwing InvalidOperationException at render.
/// It also covers the cover image round trip: the detail banner and the list's wide thumbnail both pick up the filled URL.
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
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/collectibles");
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        list = await detail.OpenCollectiblesAsync();
        // ItemImageShape="wide", as in VideoGames.razor, pinning the rendered shape, not only that an image exists.
        await list.ExpectRowThumbnailAsync(title, imageUrl);

        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
