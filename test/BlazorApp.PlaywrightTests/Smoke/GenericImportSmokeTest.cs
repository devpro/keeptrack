using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Drives the generic store/CSV import UI end to end (upload → preview → commit → result), the browser-level
/// coverage the API-only <c>GenericImportResourceTest</c> can't provide. The fixture row carries a "Type"
/// column of Book, so it's pre-selected from the file rather than any heuristic. Uses a GUID-suffixed book
/// title (and a fresh order id inside the fixture) so every run imports a genuinely new book it then deletes.
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

        try
        {
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
        finally
        {
            foreach (var id in await Fixture.GetItemIdsAsync($"/api/books?search={Uri.EscapeDataString(title)}"))
            {
                await Fixture.DeleteItemAsync($"/api/books/{id}");
            }
        }
    }
}
