using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The <c>/import/amazon</c> sub-page: upload an order-history CSV, review the parsed rows, then commit the selected ones.
/// </summary>
public class AmazonImportPage(IPage page) : PageBase(page)
{
    protected override string? Route => "/import/amazon";

    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Amazon", Level = 1 })).ToBeVisibleAsync();
    }

    /// <summary>
    /// Scoped by <c>accept</c>, the same way <see cref="ImportPage"/> disambiguates its three dropzones: this
    /// page has one file input, but the hub it is reached from has three, so an unscoped locator turns a missed
    /// navigation into "strict mode violation: resolved to 3 elements" instead of a wait.
    /// </summary>
    private ILocator FileInput => Page.Locator(".kt-dropzone input[type='file'][accept='.csv']");

    /// <summary>
    /// Only rendered once a preview exists; its label carries the selected-row count (e.g. "Import selected (1)"),
    /// so asserting on its text proves the upload parsed and pre-selected the expected rows.
    /// </summary>
    public ILocator CommitButton => Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Import selected" });

    /// <summary>The result banner rendered after a successful commit.</summary>
    public ILocator ResultAlert => Page.Locator(".alert-info");

    public async Task UploadAsync(byte[] csv, string fileName)
        => await FileInput.SetInputFilesAsync(new FilePayload { Name = fileName, MimeType = "text/csv", Buffer = csv });

    public async Task CommitSelectedAsync() => await CommitButton.ClickAsync();
}
