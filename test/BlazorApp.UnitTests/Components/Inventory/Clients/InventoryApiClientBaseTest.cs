using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.WebApi.Contracts.Dto;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Inventory.Clients;

/// <summary>
/// Covers the one branch every detail page depends on: a 404 has to come back as null so the page can render
/// its own "not found" state, instead of throwing and surfacing the generic error page for a dead link.
/// Exercised through <see cref="MovieApiClient"/> because the base class is abstract - the behaviour under test
/// is the base's, and is shared by all eleven detail pages.
/// </summary>
[Trait("Category", "UnitTests")]
public class InventoryApiClientBaseTest
{
    private sealed class StubHandler(HttpStatusCode statusCode, HttpContent? content = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode) { Content = content ?? new StringContent(string.Empty) });
    }

    private static MovieApiClient ClientReturning(HttpStatusCode statusCode, HttpContent? content = null) =>
        new(new HttpClient(new StubHandler(statusCode, content)) { BaseAddress = new Uri("https://api.example") });

    [Fact]
    public async Task GetOneAsync_ReturnsNull_ForAnItemTheApiReports404For()
    {
        var movie = await ClientReturning(HttpStatusCode.NotFound).GetOneAsync("missing-id", TestContext.Current.CancellationToken);

        movie.Should().BeNull();
    }

    [Fact]
    public async Task GetOneAsync_ReturnsTheItem_WhenItExists()
    {
        var client = ClientReturning(HttpStatusCode.OK, JsonContent.Create(new MovieDto { Id = "abc", Title = "Heat" }));

        var movie = await client.GetOneAsync("abc", TestContext.Current.CancellationToken);

        movie.Should().NotBeNull();
        movie!.Title.Should().Be("Heat");
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task GetOneAsync_StillThrows_ForAFailureThatIsNotAMissingItem(HttpStatusCode statusCode)
    {
        // only "it isn't there" is an expected answer - swallowing the rest would render a real outage
        // as an empty detail page.
        var get = async () => await ClientReturning(statusCode).GetOneAsync("abc");

        await get.Should().ThrowAsync<HttpRequestException>();
    }
}
