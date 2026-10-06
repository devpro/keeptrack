using System.IO;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the admin reference-data page's provider-free, deterministic surfaces end to end:
/// the page loads for an admin (through the Admin nav link), its System status panel resolves, and the unresolved queue switches type.
/// The export and import round trip works through the real UI, and re-importing changes nothing, since the import matches by provider id.
/// The per-type detail page smoke tests cover the provider search and link, and a full sync-now poll is not driven, since it flakes on provider latency.
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
