using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers the wishlist share-link lifecycle end-to-end: several independent labeled links per owner,
/// the anonymous token read (verified with a second HttpClient that never authenticates - the whole
/// point of the feature), and revoking one link without touching the others.
/// </summary>
public class WishlistShareResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task ShareEndpoints_RequireAuthentication()
    {
        await GetAsync("/api/wishlist/shares", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Shares_AreIndependentlyCreatableListableAndRevocable_AndReadableAnonymously()
    {
        await Authenticate();

        // a wishlisted movie that must appear in the shared view
        var movie = await PostAsync<MovieDto>("/api/movies", new MovieDto { Title = $"SharedWishlistTarget-{Guid.NewGuid():N}", IsWishlisted = true });

        var mumShare = await PostAsync<CreateWishlistShareRequestDto, WishlistShareDto>("/api/wishlist/shares", new CreateWishlistShareRequestDto { Label = "Mum" });
        var friendShare = await PostAsync<CreateWishlistShareRequestDto, WishlistShareDto>("/api/wishlist/shares", new CreateWishlistShareRequestDto { Label = "Friend" });
        mumShare.Token.Should().NotBeNullOrEmpty().And.NotBe(friendShare.Token);
        mumShare.Label.Should().Be("Mum");

        // a genuinely anonymous client - no Authenticate(), no bearer header, like a share recipient
        using var anonymous = new HttpClient { BaseAddress = new Uri(Factory.ServerAddress) };
        try
        {
            var shares = await GetAsync<List<WishlistShareDto>>("/api/wishlist/shares");
            shares.Should().Contain(s => s.Id == mumShare.Id && s.Label == "Mum");
            shares.Should().Contain(s => s.Id == friendShare.Id && s.Label == "Friend");

            var shared = await anonymous.GetFromJsonAsync<WishlistDto>($"/api/wishlist/shared/{mumShare.Token}", TestContext.Current.CancellationToken);
            shared!.Movies.Should().Contain(m => m.Id == movie.Id);

            // an unknown token is an indistinguishable 404
            (await anonymous.GetAsync($"/api/wishlist/shared/{Guid.NewGuid():N}", TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.NotFound);

            // revoking one link kills that link only - the other keeps working
            await DeleteAsync($"/api/wishlist/shares/{mumShare.Id}");
            (await anonymous.GetAsync($"/api/wishlist/shared/{mumShare.Token}", TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.NotFound);
            (await anonymous.GetAsync($"/api/wishlist/shared/{friendShare.Token}", TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);

            var remaining = await GetAsync<List<WishlistShareDto>>("/api/wishlist/shares");
            remaining.Should().NotContain(s => s.Id == mumShare.Id);
            remaining.Should().Contain(s => s.Id == friendShare.Id);
        }
        finally
        {
            await DeleteAsync($"/api/movies/{movie.Id}");
            await DeleteAsync($"/api/wishlist/shares/{mumShare.Id}");
            await DeleteAsync($"/api/wishlist/shares/{friendShare.Id}");
        }
    }
}
