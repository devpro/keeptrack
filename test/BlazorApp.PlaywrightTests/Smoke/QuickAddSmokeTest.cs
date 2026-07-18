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
/// Runs alone, same rationale as <see cref="WatchNextSmokeTestCollection"/>: the car-record scenario
/// below asserts the shared tenant has exactly one car (the single-parent silent-preselect path), which
/// a parallel class's own car create/delete traffic (e.g. <c>CarSmokeTest</c>, <c>MobileScreenshotTest</c>)
/// would otherwise race.
/// </summary>
[CollectionDefinition(nameof(QuickAddSmokeTest), DisableParallelization = true)]
public class QuickAddSmokeTestCollection;

/// <summary>
/// Quick Add's own end-to-end coverage: one media type (Movie, exercising the "I own a copy" toggle that
/// shares OwnedVersionFields with OwnedVersionsEditor) and one record type (a car refuel, exercising the
/// single-parent silent-preselect path and the shared CarHistoryForm). The other six types reuse the same
/// shared form components already covered from their own detail pages
/// (TvShowSmokeTest/BookSmokeTest/AlbumSmokeTest/VideoGamePlatformSmokeTest/HouseSmokeTest/HealthSmokeTest),
/// so this class doesn't repeat one scenario per type - it only needs to prove Quick Add's own plumbing
/// (picker navigation, single-POST save, landing route) works, which one media type and one record type
/// already demonstrate.
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

        await BookDetailPage.SetFieldAsync(quickAdd.TitleInput, title);
        await Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "I own a copy" }).ClickAsync();
        await BookDetailPage.SetFieldAsync(Page.GetByTestId("version-price-input"), "19.99");
        await quickAdd.SaveButton.ClickAsync();

        var detail = new MovieDetailPage(Page);
        await detail.WaitForReadyAsync();
        var movieId = ExtractIdFromUrl(Page.Url);

        try
        {
            await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(title);
            await Assertions.Expect(Page.GetByTestId("version-price-input")).ToHaveValueAsync("19.99");
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/movies/{movieId}");
        }
    }

    [Fact]
    public async Task QuickAddCarRecord_WithASingleExistingCar_PreselectsItAndSavesTheRefuel()
    {
        SkipIfReadOnly();

        var carName = $"E2e QuickAdd Car {Guid.NewGuid():N}";
        var mileage = Random.Shared.Next(100_000, 999_999);

        var carId = await CreateCarAsync(carName);

        try
        {
            var home = await new HomePage(Page).OpenAsync();
            var quickAdd = await home.OpenQuickAddAsync();
            await quickAdd.SelectTypeAsync("car");

            // the tenant now has exactly one car - it's preselected silently, no segmented picker to click
            await BookDetailPage.SetFieldAsync(Page.GetByTestId("mileage-input"), mileage.ToString());
            await BookDetailPage.SetFieldAsync(Page.GetByTestId("cost-input"), "65.40");
            await quickAdd.SaveButton.ClickAsync();

            var detail = new CarDetailPage(Page);
            await detail.WaitForReadyAsync();
            await Assertions.Expect(detail.TitleInput).ToHaveValueAsync(carName);
            await Assertions.Expect(Page.Locator(".kt-car-sheet")).ToContainTextAsync(mileage.ToString());
        }
        finally
        {
            await Fixture.DeleteItemAsync($"/api/cars/{carId}");
        }
    }

    private async Task<string> CreateCarAsync(string name)
    {
        var response = await Fixture.ApiHttpClient.PostAsJsonAsync("api/cars", new CarDto { Name = name, EnergyType = CarEnergyType.Combustion });
        response.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return body.RootElement.GetProperty("id").GetString()!;
    }
}
