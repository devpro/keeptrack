using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the generic video-game (PSN-style) transaction import UI end to end (upload → preview → commit → result),
/// the browser-level coverage the API-only <c>GenericVideoGameImportResourceTest</c> can't provide.
/// Uses a GUID-suffixed title (and fresh transaction/order ids inside the fixture) so every run imports a genuinely new game it then deletes.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class GenericVideoGameImportSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task UploadPreviewAndCommit_ImportsAVideoGameFromATransactionCsv()
    {
        SkipIfReadOnly();

        var title = $"E2e VideoGame Import {Guid.NewGuid():N}";
        var csv = GenericVideoGameImportFixtureCsvBuilder.Build(title);

        // the commit creates an item whose id this test never sees, so cleanup is keyed on the
        // fixture's own unique title - and registered before the upload, so a partial import is cleaned up too
        TrackItemsMatching("/api/video-games", $"/api/video-games?search={Uri.EscapeDataString(title)}");

        var home = await new HomePage(Page).OpenAsync();
        var import = await home.OpenImportAsync();
        var videoGames = await import.GoToVideoGameImportAsync();

        await videoGames.UploadAsync(csv, "video-game-transactions.csv");

        // The single row is auto-selected with its platform pre-filled from the CSV, so exactly one row is ready to commit.
        await Assertions.Expect(videoGames.CommitButton).ToContainTextAsync("(1)");
        await videoGames.CommitSelectedAsync();

        await Assertions.Expect(videoGames.ResultAlert).ToContainTextAsync("Video games:");
        await Assertions.Expect(videoGames.ResultAlert).ToContainTextAsync("1 created");
    }
}
