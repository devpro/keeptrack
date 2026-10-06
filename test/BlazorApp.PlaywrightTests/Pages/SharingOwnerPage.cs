using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The owner's grant-management page (<c>/account/manage/sharing</c>): create a share to an email for a set of categories, and see/revoke active shares.
/// </summary>
public class SharingOwnerPage(IPage page) : PageBase(page)
{
    public async Task<SharingOwnerPage> OpenAsync()
    {
        await Page.GotoAsync("/account/manage/sharing");
        await WaitForReadyAsync();
        return this;
    }

    protected override async Task AssertReadyAsync()
    {
        await base.AssertReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Sharing", Level = 1 })).ToBeVisibleAsync();
    }

    public async Task FillRecipientEmailAsync(string email) => await Page.GetByTestId("share-recipient-email").FillAsync(email);

    public async Task FillLabelAsync(string label) => await Page.GetByPlaceholder("Who is it for? (e.g. Mum)").FillAsync(label);

    /// <summary>
    /// Toggles a category button.
    /// The buttons share <c>data-testid="share-category"</c>, so they're picked by visible text,
    /// scoped to the new-share card, since the category name appears elsewhere too (the sidebar).
    /// Health opens a confirmation instead of toggling (see <see cref="ConfirmHealthShareAsync"/>),
    /// so unlike every other category its click isn't retried against an "active" result.
    /// <para>
    /// The first call doubles as the page's circuit warm-up, like <see cref="ReferenceDataAdminPage.SelectUnresolvedTypeAsync"/>.
    /// A plain <c>ClickAsync</c> could land between Blazor Server's static prerender and its SignalR circuit connecting, silently doing nothing.
    /// A <c>FillAsync</c> issued through <see cref="FillRecipientEmailAsync"/> or <see cref="FillLabelAsync"/> before the circuit connects changes only the DOM,
    /// and Blazor's first interactive render wipes it.
    /// Callers must toggle a category before filling the text fields, not after.
    /// </para>
    /// </summary>
    public async Task ToggleCategoryAsync(string category)
    {
        var button = Page.Locator(".kt-form-card").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = category, Exact = true });
        if (category == "Health")
        {
            await button.ClickAsync();
            return;
        }

        await ClickUntilAsync(button, Page.Locator(".kt-form-card button.kt-toggle-btn.active", new PageLocatorOptions { HasText = category }));
    }

    public async Task ConfirmHealthShareAsync()
        => await Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Share health", Exact = true }).ClickAsync();

    public async Task CreateShareAsync() => await Page.GetByTestId("share-create").ClickAsync();

    /// <summary>An active-share row, located by any distinguishing text it carries (the label or recipient email).</summary>
    public ILocator ActiveShareRow(string text) => Page.Locator(".kt-item-row", new PageLocatorOptions { HasText = text });
}
