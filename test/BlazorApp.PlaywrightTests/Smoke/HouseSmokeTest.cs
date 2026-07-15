using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Houses have no reference-data concept (confirmed: no <c>ReferenceId</c> on <c>HouseDto</c>), so this is a
/// plain add/verify/delete CRUD smoke test.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class HouseSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddAndDelete_HouseThroughTheList()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke House {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenHousesAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        // Houses redirects straight to the detail page on save.
        var detail = new HouseDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        list = await detail.OpenHousesAsync();
        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }
}
