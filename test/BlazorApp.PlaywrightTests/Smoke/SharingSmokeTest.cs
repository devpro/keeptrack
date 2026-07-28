using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// The full sharing loop, self-shared to the fixture's own email (the recipient is matched by email
/// server-side). Media is list-only with an "In collection" badge (a self-share already owns everything);
/// personal data (cars) is list plus a read-only detail page. The grant is created through the owner UI, then
/// the recipient views are exercised end to end.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class SharingSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task ShareMediaAndPersonal_RecipientSeesReadOnlyViews()
    {
        SkipIfReadOnly();

        var tag = Guid.NewGuid().ToString("N")[..8];
        var movieTitle = $"E2e Share Movie {tag}";
        var carName = $"E2e Share Car {tag}";
        var label = $"E2e {tag}";
        var api = Fixture.ApiHttpClient;

        var movie = await CreateAsync<MovieDto>(api, "api/movies", new MovieDto { Title = movieTitle, Year = 1999 });
        var car = await CreateAsync<CarDto>(api, "api/cars", new CarDto { Name = carName, EnergyType = CarEnergyType.Combustion });
        await CreateAsync<CarHistoryDto>(api, "api/car-history", new CarHistoryDto
        {
            CarId = car.Id!,
            HistoryDate = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            EventType = CarHistoryType.Maintenance,
            Cost = 120.50
        });

        string? shareId = null;
        try
        {
            // Owner creates the grant (Movies + Cars) through the profile UI.
            var sharing = await new SharingOwnerPage(Page).OpenAsync();
            await sharing.FillRecipientEmailAsync(Fixture.SignedInEmail);
            await sharing.FillLabelAsync(label);
            await sharing.ToggleCategoryAsync("Movies");
            await sharing.ToggleCategoryAsync("Cars");
            await sharing.CreateShareAsync();
            await Assertions.Expect(sharing.ActiveShareRow(label)).ToBeVisibleAsync();

            shareId = await FindShareIdByLabelAsync(api, label);

            // Recipient: the sharer shows up in "Shared with me", then their collection opens with tabs.
            var sharedWithMe = await new SharedWithMePage(Page).OpenAsync();
            await Assertions.Expect(sharedWithMe.PersonRow.First).ToBeVisibleAsync();
            var collection = await sharedWithMe.OpenCollectionByIdAsync(shareId);

            // Media (Movies): listed, read-only, already-in-collection (self-share) so it carries the badge.
            await collection.SelectTabAsync("Movies");
            await Assertions.Expect(collection.Row(movieTitle)).ToBeVisibleAsync();
            await Assertions.Expect(collection.InCollectionBadge(movieTitle)).ToBeVisibleAsync();

            // Personal (Cars): listed, and opens a full read-only detail page (title not editable, no add).
            await collection.SelectTabAsync("Cars");
            await Assertions.Expect(collection.Row(carName)).ToBeVisibleAsync();
            var carDetail = await collection.OpenCarAsync(carName);
            await Assertions.Expect(carDetail.TitleInput).ToBeDisabledAsync();
            await Assertions.Expect(Page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "+ Add entry" })).ToHaveCountAsync(0);
        }
        finally
        {
            if (shareId is not null)
            {
                await Fixture.DeleteItemAsync($"api/shares/{shareId}");
            }
            await Fixture.DeleteItemAsync($"api/movies/{movie.Id}");
            await Fixture.DeleteItemAsync($"api/cars/{car.Id}");
        }
    }

    private static async Task<T> CreateAsync<T>(HttpClient api, string path, T body)
    {
        var response = await api.PostAsJsonAsync(path, body, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<T>(TestContext.Current.CancellationToken))!;
    }

    private static async Task<string> FindShareIdByLabelAsync(HttpClient api, string label)
    {
        var shares = await api.GetFromJsonAsync<List<ShareDto>>("api/shares", TestContext.Current.CancellationToken);
        return shares!.First(s => s.Label == label).Id;
    }
}
