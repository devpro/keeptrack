using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class CarSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddAndDelete_CarThroughTheList()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke Car {Guid.NewGuid():N}";
        const string imageUrl = "https://picsum.photos/seed/e2e-car/600/300";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenCarsAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        var detail = new CarDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        // cover image: the detail banner and the list's wide thumbnail (same shape as VideoGames.razor)
        // must both pick up the URL - a plain default-portrait thumb was a reported regression here.
        await DetailPageBase.SetFieldAsync(detail.ImageUrlInput, imageUrl);
        await Assertions.Expect(detail.CoverImage).ToHaveAttributeAsync("src", imageUrl);

        list = await detail.OpenCarsAsync();
        await Assertions.Expect(list.Row(name).Locator(".kt-item-thumb.wide img")).ToHaveAttributeAsync("src", imageUrl);

        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }
}
