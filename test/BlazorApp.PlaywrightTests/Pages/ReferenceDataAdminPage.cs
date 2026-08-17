using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The admin-only <c>/admin/reference-data</c> page: the unresolved-title queue (per reference type), the sync-now control,
/// the export/import round-trip, and the System status panel.
/// The smoke test deliberately drives only the provider-free, deterministic surfaces here -
/// the provider search/link flow is already covered by the per-type detail-page smoke tests, and a full sync-now poll is known to flake on provider latency.
/// </summary>
public class ReferenceDataAdminPage(IPage page) : PageBase(page)
{
    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Reference data", Level = 1 })).ToBeVisibleAsync();
    }

    /// <summary>A System-panel row that only renders once the (admin-only) status call has resolved - proof the panel loaded.</summary>
    public ILocator SystemInstanceRow => Page.GetByText("Answered by instance");

    private ILocator TypeButton(string name) => Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = name, Exact = true });

    /// <summary>
    /// Switches the unresolved queue to another reference type and waits for that type's button to read back as the active (primary) one.
    /// Uses the same first-click-after-load retry as the list pages, so it doubles as the circuit-warmup before the export click below.
    /// </summary>
    public async Task SelectUnresolvedTypeAsync(string typeButtonName)
        => await ClickUntilAsync(TypeButton(typeButtonName), Page.Locator("button.btn-primary", new PageLocatorOptions { HasText = typeButtonName }));

    private ILocator ExportButton => Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Download export" });

    /// <summary>The import file input (the only file input on the page - the export is a button, not a file input).</summary>
    private ILocator ImportFileInput => Page.Locator("input[type='file'][accept='.zip']");

    public ILocator ImportResultAlert => Page.Locator(".alert-info", new PageLocatorOptions { HasText = "Imported" });

    /// <summary>Clicks "Download export" and saves the browser download to a temp path the caller owns (and deletes).</summary>
    public async Task<string> DownloadExportAsync()
    {
        var download = await Page.RunAndWaitForDownloadAsync(async () => await ExportButton.ClickAsync());
        var path = Path.Combine(Path.GetTempPath(), $"kt-e2e-ref-export-{Guid.NewGuid():N}.zip");
        await download.SaveAsAsync(path);
        return path;
    }

    public async Task ImportExportAsync(string zipPath) => await ImportFileInput.SetInputFilesAsync(zipPath);
}
