using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers the wishlist share-link lifecycle end-to-end: create (idempotent), the anonymous token read
/// (verified with a second HttpClient that never authenticates - the whole point of the feature), and
/// revocation killing the link.
/// </summary>
public class WishlistShareResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task ShareEndpoints_RequireAuthentication()
    {
        await GetAsync("/api/wishlist/share", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task SharedWishlist_IsReadableAnonymously_AndRevocationKillsTheLink()
    {
        await Authenticate();

        // a wishlisted movie that must appear in the shared view
        var movie = await PostAsync<MovieDto>("/api/movies", new MovieDto { Title = $"SharedWishlistTarget-{Guid.NewGuid():N}", IsWishlisted = true });

        // create is idempotent: a second POST returns the same token instead of rotating it
        var share = await PostAsync<WishlistShareDto?>("/api/wishlist/share", null, HttpStatusCode.OK);
        share!.Token.Should().NotBeNullOrEmpty();
        var again = await PostAsync<WishlistShareDto?>("/api/wishlist/share", null, HttpStatusCode.OK);
        again!.Token.Should().Be(share.Token);

        // a genuinely anonymous client - no Authenticate(), no bearer header, like a share recipient
        using var anonymous = new HttpClient { BaseAddress = new Uri(Factory.ServerAddress) };
        try
        {
            var shared = await anonymous.GetFromJsonAsync<WishlistDto>($"/api/wishlist/shared/{share.Token}");
            shared!.Movies.Should().Contain(m => m.Id == movie.Id);

            // an unknown token is an indistinguishable 404
            (await anonymous.GetAsync($"/api/wishlist/shared/{Guid.NewGuid():N}")).StatusCode.Should().Be(HttpStatusCode.NotFound);

            // revoking makes every copy of the link dead immediately
            await DeleteAsync("/api/wishlist/share");
            (await anonymous.GetAsync($"/api/wishlist/shared/{share.Token}")).StatusCode.Should().Be(HttpStatusCode.NotFound);
            await GetAsync("/api/wishlist/share", HttpStatusCode.NotFound);
        }
        finally
        {
            await DeleteAsync($"/api/movies/{movie.Id}");
            await DeleteAsync("/api/wishlist/share", HttpStatusCode.NoContent);
        }
    }
}
