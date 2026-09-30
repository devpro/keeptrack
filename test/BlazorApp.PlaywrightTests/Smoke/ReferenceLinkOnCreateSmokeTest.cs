using System.Collections.Generic;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// A title that resolves on creation shows its link on the detail page the Add form opens, with no click and no reload.
/// </summary>
/// <remarks>
/// Creating an item resolves its reference on a detached background task, so whether the detail page's first read already sees the link depends on how fast the provider answers.
/// Every reference-linked detail page watches for the link (<c>PendingReferenceLink</c>) so a slow provider still ends in a linked page.
/// A fast provider wins the race without that watch, which is why this test guards the journey rather than proving the watch on its own.
/// The titles are real, resolve unattended (one confirmed match on the domain's default provider), and are used by no other journey test.
/// The references they resolve are removed afterwards, since a leftover lets the server link from its local aliases instead of asking the provider.
/// </remarks>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ReferenceLinkOnCreateSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    /// <summary>
    /// Longer than the page's own watch, which gives up after about nine seconds, so a failure here means the page never showed the link rather than showed it late.
    /// </summary>
    private const float LinkVisibleTimeoutMs = 20_000;

    private static readonly Dictionary<string, string> ReferenceCollections = new()
    {
        ["movies"] = "movie_reference",
        ["tv-shows"] = "tvshow_reference",
        ["albums"] = "album_reference",
        ["video-games"] = "videogame_reference"
    };

    [Theory]
    [InlineData("movies")]
    [InlineData("tv-shows")]
    [InlineData("albums")]
    [InlineData("video-games")]
    public async Task CreatingAResolvableTitle_ShowsItsCoverWithoutAReload(string type)
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        DetailPageBase detail;
        switch (type)
        {
            case "movies":
                {
                    var list = await home.OpenMoviesAsync();
                    await list.ClickAddAsync();
                    await list.FillAsync("title-input", "Whiplash");
                    await list.FillAsync("year-input", "2014");
                    await list.SaveNewAsync();
                    detail = new MovieDetailPage(Page);
                    break;
                }
            case "tv-shows":
                {
                    var list = await home.OpenTvShowsAsync();
                    await list.ClickAddAsync();
                    await list.FillAsync("title-input", "Severance");
                    await list.FillAsync("year-input", "2022");
                    await list.SaveNewAsync();
                    detail = new TvShowDetailPage(Page);
                    break;
                }
            case "albums":
                {
                    var list = await home.OpenAlbumsAsync();
                    await list.ClickAddAsync();
                    await list.FillAsync("title-input", "Kid A");
                    await list.FillAsync("artist-input", "Radiohead");
                    await list.FillAsync("year-input", "2000");
                    await list.SaveNewAsync();
                    detail = new AlbumDetailPage(Page);
                    break;
                }
            default:
                {
                    var list = await home.OpenVideoGamesAsync();
                    await list.ClickAddAsync();
                    await list.FillByPlaceholderAsync("Title", "Stardew Valley");
                    await list.FillByPlaceholderAsync("Year", "2016");
                    await list.SaveNewAsync();
                    detail = new VideoGameDetailPage(Page);
                    break;
                }
        }

        await detail.WaitForReadyAsync();
        TrackOpenItem($"/api/{type}");
        var id = ExtractIdFromUrl(Page.Url);
        TrackCleanup(async () =>
        {
            var item = await Fixture.ApiHttpClient.GetFromJsonAsync<JsonElement>($"/api/{type}/{id}", CancellationToken.None);
            if (item.TryGetProperty("referenceId", out var referenceId) && referenceId.ValueKind == JsonValueKind.String)
            {
                await Fixture.RemoveReferencesAsync(ReferenceCollections[type], [referenceId.GetString()!]);
            }
        });

        await Assertions.Expect(detail.CoverImage.First).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = LinkVisibleTimeoutMs });
    }
}
