using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, well-known album so linking exercises the actual Discogs provider -
/// Album is one of the two domains (with Book) that also passes a Creator (Artist) to narrow the search.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class AlbumSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    private const string Title = "Nevermind";
    private const string Artist = "Nirvana";
    private const string Year = "1991";

    [Fact]
    public async Task AddLinkAndDelete_AlbumThroughTheList()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenAlbumsAsync();
        await list.ClickAddAsync();
        await list.FillAsync("title-input", Title);
        await list.FillAsync("artist-input", Artist);
        await list.FillAsync("year-input", Year);
        await list.SaveNewAsync();

        var detail = new AlbumDetailPage(Page);
        await detail.WaitForReadyAsync();
        var id = ExtractIdFromUrl(Page.Url);

        try
        {
            await detail.SearchAndLinkFirstResultAsync();

            await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
            await Assertions.Expect(detail.ArtistInput).ToHaveValueAsync(Artist);
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/albums/{id}");
        }
    }
}
