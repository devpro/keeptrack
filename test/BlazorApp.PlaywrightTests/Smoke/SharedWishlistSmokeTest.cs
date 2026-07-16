using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Proves the shared-wishlist link works for its actual audience: a browser with no session at all.
/// The share is created through the API (the owner-side UI panel is a thin wrapper over the same
/// endpoints), then the page is opened in a fresh, unauthenticated browser context - the one flow
/// no other e2e test exercises, since they all start from the fixture's signed-in storage state.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Mutating")]
public class SharedWishlistSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task SharedWishlist_IsViewableWithoutSigningIn()
    {
        SkipIfReadOnly();

        var title = $"E2e Shared Wishlist Movie {Guid.NewGuid():N}";
        var api = Fixture.ApiHttpClient;

        var createResponse = await api.PostAsJsonAsync("api/movies", new MovieDto { Title = title, IsWishlisted = true });
        createResponse.EnsureSuccessStatusCode();
        var movie = (await createResponse.Content.ReadFromJsonAsync<MovieDto>())!;

        var shareResponse = await api.PostAsJsonAsync("api/wishlist/shares", new CreateWishlistShareRequestDto { Label = "E2e recipient" });
        shareResponse.EnsureSuccessStatusCode();
        var share = (await shareResponse.Content.ReadFromJsonAsync<WishlistShareDto>())!;

        try
        {
            // a brand-new context: no cookies, no storage state - a share recipient's browser
            await using var anonymousContext = await Browser.NewContextAsync(new BrowserNewContextOptions
            {
                BaseURL = Fixture.BlazorBaseUrl,
                IgnoreHTTPSErrors = true
            });
            var page = await anonymousContext.NewPageAsync();

            await page.GotoAsync($"/shared/wishlist/{share.Token}");
            await Assertions.Expect(page.GetByText(title)).ToBeVisibleAsync();
            // the sign-up invitation for recipients who want their own collection
            await Assertions.Expect(page.GetByRole(AriaRole.Link, new PageGetByRoleOptions { Name = "Get started" })).ToBeVisibleAsync();

            // a revoked link dies immediately
            (await api.DeleteAsync($"api/wishlist/shares/{share.Id}")).EnsureSuccessStatusCode();
            await page.ReloadAsync();
            await Assertions.Expect(page.GetByText("no longer valid")).ToBeVisibleAsync();
        }
        finally
        {
            await Fixture.DeleteItemAsync($"api/movies/{movie.Id}");
            await Fixture.DeleteItemAsync($"api/wishlist/shares/{share.Id}");
        }
    }
}
