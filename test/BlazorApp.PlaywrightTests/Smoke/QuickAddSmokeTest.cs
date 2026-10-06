using System;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Runs alone, like <see cref="WatchNextSmokeTestCollection"/>, since the car record scenario asserts the tenant has exactly one car (the single-parent preselect path), which a parallel class's car traffic (<c>CarSmokeTest</c>, <c>MobileScreenshotTest</c>) would race.
/// </summary>
[CollectionDefinition(nameof(QuickAddSmokeTest), DisableParallelization = true)]
public class QuickAddSmokeTestCollection;

/// <summary>
/// Quick Add's end-to-end coverage: one media type (a movie, with the "I own a copy" toggle sharing OwnedVersionFields) and one record type (a car refuel, with the single-parent preselect and the shared CarHistoryForm).
/// The other six types reuse form components their own detail page smoke tests cover, so this proves only Quick Add's plumbing: picker navigation, single-POST save, landing route.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
[Collection(nameof(QuickAddSmokeTest))]
public class QuickAddSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task QuickAddMovie_WithAnOwnedCopy_LandsOnItsDetailPageWithTheCopySaved()
    {
        SkipIfReadOnly();

        var title = $"E2e QuickAdd Movie {Guid.NewGuid():N}";

        var home = await new HomePage(Page).OpenAsync();
        var quickAdd = await home.OpenQuickAddAsync();
        await quickAdd.SelectTypeAsync("movie");

        await DetailPageBase.SetFieldAsync(quickAdd.TitleInput, title);
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "I own a copy" }).ClickAsync();
        await DetailPageBase.SetFieldAsync(Page.GetByTestId("version-price-input"), "19.99");
        await quickAdd.SaveButton.ClickAsync();

        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        TrackOpenItem("/api/movies");

        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);
        await Assertions.Expect(Page.GetByTestId("version-price-input")).ToHaveValueAsync("19.99");
    }

    [Fact]
    public async Task QuickAddCarRecord_WithASingleExistingCar_PreselectsItAndSavesTheRefuel()
    {
        SkipIfReadOnly();

        var carName = $"E2e QuickAdd Car {Guid.NewGuid():N}";
        var mileage = Random.Shared.Next(100_000, 999_999);

        await CreateItemAsync("api/cars", new CarDto { Name = carName, EnergyType = CarEnergyType.Combustion });

        var home = await new HomePage(Page).OpenAsync();
        var quickAdd = await home.OpenQuickAddAsync();
        await quickAdd.SelectTypeAsync("car");

        // the tenant has exactly one car, preselected with no segmented picker to click
        await DetailPageBase.SetFieldAsync(Page.GetByTestId("mileage-input"), mileage.ToString());
        await DetailPageBase.SetFieldAsync(Page.GetByTestId("cost-input"), "65.40");
        await quickAdd.SaveButton.ClickAsync();

        var detail = new CarDetailPage(Page);
        await detail.WaitForReadyAsync();
        await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(carName);
        await Assertions.Expect(Page.Locator(".kt-car-sheet")).ToContainTextAsync(mileage.ToString());
    }
}
