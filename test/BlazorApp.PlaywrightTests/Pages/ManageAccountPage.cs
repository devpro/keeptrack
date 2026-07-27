using System.Threading.Tasks;
using Microsoft.Playwright;

namespace Keeptrack.BlazorApp.PlaywrightTests.Pages;

/// <summary>
/// The <c>/account/manage</c> page: the signed-in identity summary plus the user-preference toggles.
/// </summary>
public class ManageAccountPage(IPage page) : PageBase(page)
{
    public async Task<ManageAccountPage> OpenAsync()
    {
        await Page.GotoAsync("/account/manage");
        await WaitForReadyAsync();
        return this;
    }

    public override async Task WaitForReadyAsync()
    {
        await base.WaitForReadyAsync();
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Manage", Level = 1 })).ToBeVisibleAsync();
    }

    /// <summary>The "Signed in as {email}" line - proof the authenticated identity rendered.</summary>
    public ILocator SignedInAs => Page.GetByText("Signed in as");

    /// <summary>One of the two preference checkboxes; it carries a real <c>&lt;label for&gt;</c>, so <c>GetByLabel</c> resolves it.</summary>
    public ILocator ChasseAuxLivresPreference => Page.GetByLabel("Show chasse-aux-livres.fr link on book pages");
}
