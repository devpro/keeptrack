using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Cars have no reference-data concept (confirmed: no <c>ReferenceId</c> on <c>CarDto</c>), so this is a
/// plain add/verify/delete CRUD smoke test.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class CarSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AddAndDelete_CarThroughTheList()
    {
        SkipIfReadOnly();

        var name = $"E2e Smoke Car {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var list = await home.OpenCarsAsync();
        await list.ClickAddAsync();
        await list.FillAsync("name-input", name);
        await list.SaveNewAsync();

        // Cars redirects straight to the detail page on save.
        var detail = new CarDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(name);

        list = await detail.OpenCarsAsync();
        await list.DeleteAsync(name);
        await Assertions.Expect(list.Row(name)).Not.ToBeVisibleAsync();
    }
}
