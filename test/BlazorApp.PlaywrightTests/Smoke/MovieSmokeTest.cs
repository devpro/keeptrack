using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, well-known movie so linking exercises the actual TMDB provider, not a synthetic fixture -
/// see the phase 4 goal of smoke testing every page's reference-linking against the real external services.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class MovieSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    private const string Title = "The Terminator";
    private const string Year = "1984";

    [Fact]
    public async Task AddLinkAndDelete_MovieThroughTheList()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenMoviesAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", Title);
        await list.FillAsync("year-input", Year);
        await list.SaveNewAsync();

        await Assertions.Expect(list.Row(Title)).ToBeVisibleAsync();
        await list.OpenItemAsync(Title);
        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        var id = ExtractIdFromUrl(Page.Url);

        try
        {
            await detail.SearchAndLinkFirstResultAsync();

            await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/movies/{id}");
        }
    }
}
