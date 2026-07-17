using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Walks the health journal end-to-end: create a profile, add an appointment through the modal (with a
/// price but no reimbursement), and check the balance surfaces both as the "Reimbursements to check"
/// panel and the row's own "to check" badge - the core promise of the feature.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class HealthSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddProfileAndUnbalancedAppointment_ThenDelete()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke Health {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenHealthAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        var detail = new HealthProfileDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        // add an appointment paid 60 with nothing reimbursed yet - it must come back flagged
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add entry" }).ClickAsync();
        // data-testid, not GetByLabel: the modal's label/input pairs have no for/id association (the
        // documented inventory-form gotcha - see CLAUDE.md's Playwright section)
        await Page.GetByTestId("practitioner-input").FillAsync("Dr E2e");
        await Page.GetByTestId("price-input").FillAsync("60");
        await Page.Locator(".kt-modal").GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Save" }).ClickAsync();

        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Reimbursements to check" })).ToBeVisibleAsync();
        await Assertions.Expect(Page.GetByText("to check").First).ToBeVisibleAsync();
        await Assertions.Expect(Page.GetByText("Dr E2e").First).ToBeVisibleAsync();

        list = await detail.OpenHealthAsync();
        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }
}
