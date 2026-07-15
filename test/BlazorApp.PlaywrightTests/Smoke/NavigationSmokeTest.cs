using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Proves every page loads with its header and no error boundary, reached the same way a real user would -
/// clicking through the sidebar from Home, not a direct URL load (each <c>Open&lt;X&gt;Async()</c> call
/// already asserts this via <see cref="PageBase.WaitForReadyAsync"/>) - read-only safe, so this is the one
/// class that also runs under <c>E2E_READONLY</c>.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class NavigationSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task Home_Loads() => await new HomePage(Page).OpenAsync();

    [Fact]
    public async Task WatchNext_Loads() => await (await new HomePage(Page).OpenAsync()).OpenWatchNextAsync();

    [Fact]
    public async Task Wishlist_Loads() => await (await new HomePage(Page).OpenAsync()).OpenWishlistAsync();

    [Fact]
    public async Task Books_Loads() => await (await new HomePage(Page).OpenAsync()).OpenBooksAsync();

    [Fact]
    public async Task Movies_Loads() => await (await new HomePage(Page).OpenAsync()).OpenMoviesAsync();

    [Fact]
    public async Task Albums_Loads() => await (await new HomePage(Page).OpenAsync()).OpenAlbumsAsync();

    [Fact]
    public async Task Playlists_Loads() => await (await new HomePage(Page).OpenAsync()).OpenPlaylistsAsync();

    [Fact]
    public async Task TvShows_Loads() => await (await new HomePage(Page).OpenAsync()).OpenTvShowsAsync();

    [Fact]
    public async Task VideoGames_Loads() => await (await new HomePage(Page).OpenAsync()).OpenVideoGamesAsync();

    [Fact]
    public async Task Cars_Loads() => await (await new HomePage(Page).OpenAsync()).OpenCarsAsync();

    [Fact]
    public async Task Houses_Loads() => await (await new HomePage(Page).OpenAsync()).OpenHousesAsync();
}
