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

        var movie = await CreateItemAsync("api/movies", new MovieDto { Title = movieTitle, Year = 1999 });
        var car = await CreateItemAsync("api/cars", new CarDto { Name = carName, EnergyType = CarEnergyType.Combustion });
        await CreateItemAsync("api/car-history", new CarHistoryDto
        {
            CarId = car.Id!,
            HistoryDate = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc),
            EventType = CarHistoryType.Maintenance,
            Cost = 120.50
        });

        // Owner creates the grant (Movies + Cars) through the profile UI.
        var sharing = await new SharingOwnerPage(Page).OpenAsync();
        await sharing.FillRecipientEmailAsync(Fixture.SignedInEmail);
        await sharing.FillLabelAsync(label);
        await sharing.ToggleCategoryAsync("Movies");
        await sharing.ToggleCategoryAsync("Cars");
        await sharing.CreateShareAsync();
        await Assertions.Expect(sharing.ActiveShareRow(label)).ToBeVisibleAsync();

        var shareId = await FindShareIdByLabelAsync(api, label);
        TrackCleanup(() => Fixture.DeleteItemAsync($"api/shares/{shareId}"));

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

    /// <summary>
    /// The collection categories (Collectibles, Gear) are the third sharing shape, distinct from the other two:
    /// a full read-only list (search / sort / filters, like media) but with no shared reference to copy - so no
    /// per-row "add to my collection" action and no "In collection" badge, and no read-only detail page either
    /// (unlike personal). This pins that view-only-list distinction, self-shared to the fixture's own email.
    /// </summary>
    [Fact]
    public async Task ShareCollections_RecipientSeesReadOnlyListWithNoAddAction()
    {
        SkipIfReadOnly();

        var tag = Guid.NewGuid().ToString("N")[..8];
        var collectibleTitle = $"E2e Share Collectible {tag}";
        var gearTitle = $"E2e Share Gear {tag}";
        var label = $"E2e Coll {tag}";
        var api = Fixture.ApiHttpClient;

        var collectible = await CreateItemAsync("api/collectibles", new CollectibleDto { Title = collectibleTitle, Brand = "Lego", Year = 2020 });
        var gear = await CreateItemAsync("api/gear", new GearDto { Title = gearTitle, Brand = "Sony", Year = 2021 });

        // Owner creates the grant (Collectibles + Gear) through the profile UI's "Collections" group.
        var sharing = await new SharingOwnerPage(Page).OpenAsync();
        await sharing.FillRecipientEmailAsync(Fixture.SignedInEmail);
        await sharing.FillLabelAsync(label);
        await sharing.ToggleCategoryAsync("Collectibles");
        await sharing.ToggleCategoryAsync("Gear");
        await sharing.CreateShareAsync();
        await Assertions.Expect(sharing.ActiveShareRow(label)).ToBeVisibleAsync();

        var shareId = await FindShareIdByLabelAsync(api, label);
        TrackCleanup(() => Fixture.DeleteItemAsync($"api/shares/{shareId}"));

        var sharedWithMe = await new SharedWithMePage(Page).OpenAsync();
        var collection = await sharedWithMe.OpenCollectionByIdAsync(shareId);

        // Collectibles: listed read-only, with no "add to my collection" action and no "In collection" badge.
        await collection.SelectTabAsync("Collectibles");
        await Assertions.Expect(collection.Row(collectibleTitle)).ToBeVisibleAsync();
        await Assertions.Expect(collection.AddButton(collectibleTitle)).ToHaveCountAsync(0);
        await Assertions.Expect(collection.InCollectionBadge(collectibleTitle)).ToHaveCountAsync(0);

        // Gear: the same view-only-list shape.
        await collection.SelectTabAsync("Gear");
        await Assertions.Expect(collection.Row(gearTitle)).ToBeVisibleAsync();
        await Assertions.Expect(collection.AddButton(gearTitle)).ToHaveCountAsync(0);
    }


    private static async Task<string> FindShareIdByLabelAsync(HttpClient api, string label)
    {
        var shares = await api.GetFromJsonAsync<List<ShareDto>>("api/shares", TestContext.Current.CancellationToken);
        return shares!.First(s => s.Label == label).Id;
    }
}
