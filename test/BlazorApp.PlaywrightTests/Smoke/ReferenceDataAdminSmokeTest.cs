using System.IO;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the admin-only reference-data page's provider-free, deterministic surfaces end to end:
/// the page loads for an admin (via the Admin nav link), its System status panel resolves, the unresolved queue switches reference type,
/// and the export → import round-trip works through the real UI (export is idempotent upsert-by-id, so re-importing changes nothing).
/// The provider search/link flow is intentionally left to the per-type detail-page smoke tests, and a full sync-now poll is intentionally not driven (it flakes on provider latency).
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class ReferenceDataAdminSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AdminPage_LoadsSystemStatus_SwitchesUnresolvedType_AndRoundTripsExportImport()
    {
        SkipIfReadOnly();

        var home = await new HomePage(Page).OpenAsync();
        var admin = await home.OpenAdminAsync();

        // The System panel only renders this row once the admin-only status call resolves.
        await Assertions.Expect(admin.SystemInstanceRow).ToBeVisibleAsync();

        // Switch the unresolved queue to another reference type (also warms the interactive circuit before the export click).
        await admin.SelectUnresolvedTypeAsync("Movies");

        var exportPath = await admin.DownloadExportAsync();
        try
        {
            await admin.ImportExportAsync(exportPath);
            await Assertions.Expect(admin.ImportResultAlert).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 30000 });
            await Assertions.Expect(admin.ImportResultAlert).ToContainTextAsync("TV show(s)");
        }
        finally
        {
            if (File.Exists(exportPath))
            {
                File.Delete(exportPath);
            }
        }
    }
}
