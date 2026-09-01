using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the Amazon order-history import UI end to end (upload → preview → commit → result),
/// the browser-level coverage the API-only <c>AmazonImportResourceTest</c> can't provide.
/// Uses a GUID-suffixed book title (and a fresh order id inside the fixture) so every run imports a genuinely new book it then deletes.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class AmazonImportSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task UploadPreviewAndCommit_ImportsABookFromAnAmazonOrderCsv()
    {
        SkipIfReadOnly();

        var title = $"E2e Amazon Book {Guid.NewGuid():N}";
        var csv = AmazonImportFixtureCsvBuilder.Build(title);

        // the commit creates an item whose id this test never sees, so cleanup is keyed on the
        // fixture's own unique title - and registered before the upload, so a partial import is cleaned up too
        TrackItemsMatching("/api/books", $"/api/books?search={Uri.EscapeDataString(title)}");

        var home = await new HomePage(Page).OpenAsync();
        var import = await home.OpenImportAsync();
        var amazon = await import.GoToAmazonImportAsync();

        await amazon.UploadAsync(csv, "amazon-orders.csv");

        // The single ISBN-bearing row is auto-selected as a Book, so the commit button reports exactly one selected row.
        await Assertions.Expect(amazon.CommitButton).ToContainTextAsync("(1)");
        await amazon.CommitSelectedAsync();

        await Assertions.Expect(amazon.ResultAlert).ToContainTextAsync("Books:");
        await Assertions.Expect(amazon.ResultAlert).ToContainTextAsync("1 created");
    }
}
