using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, well-known video game so linking exercises the actual RAWG provider.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class VideoGameSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    private const string Title = "Half-Life 2";
    private const string Year = "2004";

    [Fact]
    public async Task AddLinkAndDelete_VideoGameThroughTheList()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenVideoGamesAsync();
        await list.ClickAddAsync();
        await list.FillByPlaceholderAsync("Title", Title);
        await list.FillByPlaceholderAsync("Year", Year);
        await list.SaveNewAsync();

        // VideoGames redirects straight to the detail page on save.
        var detail = new VideoGameDetailPage(Page);
        await detail.WaitForReadyAsync();
        var id = ExtractIdFromUrl(Page.Url);

        try
        {
            await detail.SearchAndLinkFirstResultAsync();

            await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/video-games/{id}");
        }
    }
}
