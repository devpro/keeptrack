using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class HouseSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddAndDelete_HouseThroughTheList()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke House {Guid.NewGuid():N}";
        const string imageUrl = "https://picsum.photos/seed/e2e-house/600/300";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenHousesAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        var detail = new HouseDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/houses");
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        // Cover image: the detail banner and the list's wide thumbnail (the shape of VideoGames.razor) both pick up the URL.
        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        list = await detail.OpenHousesAsync();
        await list.ExpectRowThumbnailAsync(name, imageUrl);

        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }
}
