using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The <c>/import/amazon</c> sub-page: upload an order-history CSV, review the parsed rows, then commit the selected ones.
/// </summary>
public class AmazonImportPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Amazon", Level = 1 })).ToBeVisibleAsync();
    }

    private ILocator FileInput => Page.Locator(".kt-dropzone input[type='file']");

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
