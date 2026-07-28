using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The owner's grant-management page (<c>/account/manage/sharing</c>): create a share to an email for a set of
/// categories, and see/revoke active shares.
/// </summary>
public class SharingOwnerPage(IPage page) : PageBase(page)
{
    public async Task<SharingOwnerPage> OpenAsync()
    {
        await Page.GotoAsync("/account/manage/sharing");
        await WaitForReadyAsync();
        return this;
    }

    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Sharing", Level = 1 })).ToBeVisibleAsync();
    }

    public async Task FillRecipientEmailAsync(string email) => await Page.GetByTestId("share-recipient-email").FillAsync(email);

    public async Task FillLabelAsync(string label) => await Page.GetByPlaceholder("Who is it for? (e.g. Mum)").FillAsync(label);

    /// <summary>
    /// Toggles a category button. The buttons share <c>data-testid="share-category"</c>, so they're picked by
    /// their visible text, scoped to the new-share card (the category name also appears elsewhere, e.g. the
    /// sidebar). Health opens a confirmation instead of toggling directly - see <see cref="ConfirmHealthShareAsync"/>.
    /// </summary>
    public async Task ToggleCategoryAsync(string category)
        => await Page.Locator(".kt-form-card").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = category, Exact = true }).ClickAsync();

    public async Task ConfirmHealthShareAsync()
        => await Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Share health", Exact = true }).ClickAsync();

    public async Task CreateShareAsync() => await Page.GetByTestId("share-create").ClickAsync();

    /// <summary>An active-share row, located by any distinguishing text it carries (the label or recipient email).</summary>
    public ILocator ActiveShareRow(string text) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = text });
}
