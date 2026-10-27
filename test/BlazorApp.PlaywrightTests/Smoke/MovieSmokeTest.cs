using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Uses a real, well-known movie so linking exercises the actual TMDB provider, not a synthetic fixture.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public partial class MovieSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
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

        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        // registered as soon as the item exists, so an assertion failure below still removes it
        TrackOpenItem("/api/movies");

        await detail.SearchAndLinkFirstResultAsync();

        await Assertions.Expect(detail.CoverImage).ToBeVisibleAsync();
    }

    [Fact]
    public async Task Delete_FromTheDetailPage_ReturnsToTheListWithoutTheItem()
    {
        SkipIfReadOnly();
        // a title no provider holds, so no background link lands while the page is open
        const string title = "Zzq Detail Delete Movie";
        var movie = await CreateItemAsync("api/movies", new MovieDto { Title = title });

        await Page.GotoAsync($"/movies/{movie.Id}");
        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        await detail.DeleteItemAsync();

        var list = new ListPage(Page, "/movies", "Movies");
        await list.WaitForReadyAsync();
        await Assertions.Expect(Page).ToHaveURLAsync(MoviesListRegex());
        await Assertions.Expect(list.Row(title)).ToHaveCountAsync(0);
        var response = await Fixture.ApiHttpClient.GetAsync($"api/movies/{movie.Id}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [GeneratedRegex("/movies$")]
    private static partial Regex MoviesListRegex();
}
