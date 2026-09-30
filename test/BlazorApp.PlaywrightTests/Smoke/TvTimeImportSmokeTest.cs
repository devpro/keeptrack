using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the TV Time GDPR-export import UI end to end (upload the zip → the background job's progress bar → the result banner),
/// the browser-level coverage the API-only <c>TvTimeImportResourceTest</c> can't provide.
/// Uses a GUID-suffixed show title (and a fresh TV Time show id inside the fixture) so every run imports a genuinely new show it then deletes.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class TvTimeImportSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task UploadAndPoll_ImportsAShowFromATvTimeExport()
    {
        SkipIfReadOnly();

        var showTitle = $"E2e TvTime Show {Guid.NewGuid():N}";
        var zip = TvTimeImportFixtureZipBuilder.Build(showTitle);

        // registered before the upload, so a partial import is cleaned up too. Deleting the show takes its
        // imported episodes with it (TvShowController.OnDeletedAsync), which is the only way to reach them:
        // an episode is a separate top-level document keyed by show id, not something a title search finds.
        TrackCleanup(async () =>
        {
            foreach (var showId in await Fixture.GetItemIdsAsync($"/api/tv-shows?search={Uri.EscapeDataString(showTitle)}"))
            {
                await Fixture.DeleteItemAsync($"/api/tv-shows/{showId}");
            }
        });

        var home = await new HomePage(Page).OpenAsync();
        var import = await home.OpenImportAsync();

        await import.UploadTvTimeExportAsync(zip, "tv-time-export.zip");

        // The import runs as a polled background job, so the result banner can take a few seconds to appear.
        await Assertions.Expect(import.ResultAlert).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 30000 });
        await Assertions.Expect(import.ResultAlert).ToContainTextAsync("Shows:");
        await Assertions.Expect(import.ResultAlert).ToContainTextAsync("1 created");
    }
}
