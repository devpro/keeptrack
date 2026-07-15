using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Playlists have no reference-data concept at all (confirmed: no <c>ReferenceId</c> on <c>PlaylistDto</c>),
/// so this is a plain add/verify/delete CRUD smoke test - same GUID-suffixed-title discipline as
/// <c>BookSmokeTest</c> since there's no real-world title to preserve here.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class PlaylistSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddAndDelete_PlaylistThroughTheList()
    {
        SkipIfReadOnly();

        var title = $"E2e Smoke Playlist {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenPlaylistsAsync();
        await list.ClickAddAsync();
        await list.FillByPlaceholderAsync("Title", title);
        await list.SaveNewAsync();

        var detail = new PlaylistDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);

        list = await detail.OpenPlaylistsAsync();
        await list.DeleteAsync(title);
        await Assertions.Expect(list.Row(title)).Not.ToBeVisibleAsync();
    }
}
