using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The <c>/import</c> landing page. The TV Time zip upload (and the car/health spreadsheet uploads) live directly on it,
/// while the Amazon and generic-video-game importers are separate sub-pages reached via the links below.
/// </summary>
public class ImportPage(IPage page) : PageBase(page)
{
    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        // Unique to the landing page (the Amazon/video-game sub-pages don't carry this heading).
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "TV Time", Level = 1 })).ToBeVisibleAsync();
    }

    /// <summary>
    /// The TV Time upload accepts <c>.zip</c>; the car/health dropzones on the same page accept <c>.xlsx</c>,
    /// so the <c>accept</c> attribute is what disambiguates the three file inputs.
    /// </summary>
    private ILocator TvTimeFileInput => Page.Locator("input[type='file'][accept='.zip']");

    /// <summary>The single result banner rendered once an upload completes (only the TV Time flow is triggered here).</summary>
    public ILocator ResultAlert => Page.Locator(".alert-info");

    public async Task UploadTvTimeExportAsync(byte[] zip, string fileName)
        => await TvTimeFileInput.SetInputFilesAsync(new FilePayload { Name = fileName, MimeType = "application/zip", Buffer = zip });

    public async Task<AmazonImportPage> GoToAmazonImportAsync()
    {
        await Page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = "Import from Amazon" }).ClickAsync();
        var next = new AmazonImportPage(Page);
        await next.WaitForReadyAsync();
        return next;
    }

    public async Task<GenericVideoGameImportPage> GoToVideoGameImportAsync()
    {
        await Page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = "Import video game transactions" }).ClickAsync();
        var next = new GenericVideoGameImportPage(Page);
        await next.WaitForReadyAsync();
        return next;
    }
}
