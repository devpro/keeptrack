using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the generic store CSV import UI end to end (upload, preview, commit, result), the browser coverage the API-only <c>GenericImportResourceTest</c> can't provide.
/// The fixture row's "Type" column is Book, so it is preselected from the file rather than a heuristic.
/// A GUID-suffixed book title and a fresh order id make every run import a new book it then deletes.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class GenericImportSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task UploadPreviewAndCommit_ImportsABookFromAGenericCsv()
    {
        SkipIfReadOnly();

        var title = $"E2e Generic Book {Guid.NewGuid():N}";
        var csv = GenericImportFixtureCsvBuilder.Build(title);

        // The commit creates an item whose id this test never sees,
        // so cleanup is keyed on the fixture's unique title, registered before the upload, so a partial import is cleaned up too.
        TrackItemsMatching("/api/books", $"/api/books?search={Uri.EscapeDataString(title)}");

        var home = await new HomePage(Page).OpenAsync();
        var import = await home.OpenImportAsync();
        var generic = await import.GoToGenericImportAsync();

        await generic.UploadAsync(csv, "orders.csv");

        // The single row carries Type=Book, so it's auto-selected and the commit button reports one selected row.
        await Assertions.Expect(generic.CommitButton).ToContainTextAsync("(1)");
        await generic.CommitSelectedAsync();

        await Assertions.Expect(generic.ResultAlert).ToContainTextAsync("Books:");
        await Assertions.Expect(generic.ResultAlert).ToContainTextAsync("1 created");
    }
}
