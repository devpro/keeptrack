using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Clients;
using Keeptrack.BlazorApp.Components.Shared;
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

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public Uri? RequestUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new MovieDto { Id = "abc", Title = "Heat" }) });
        }
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

    [Fact]
    public async Task RefreshReferenceAsync_ReportsTheApisOwnMessage_WhenTheProviderFailed()
    {
        var client = ClientReturning(HttpStatusCode.BadGateway, JsonContent.Create(new { error = "The external provider returned 503 (ServiceUnavailable)." }));

        var refresh = async () => await client.RefreshReferenceAsync("abc", TestContext.Current.CancellationToken);

        var thrown = await refresh.Should().ThrowAsync<ApiRequestException>();
        thrown.Which.Message.Should().Be("The external provider returned 503 (ServiceUnavailable).");
        thrown.Which.IsUpstreamProviderFailure.Should().BeTrue();
    }

    [Fact]
    public async Task UnlinkReferenceAsync_ReportsTheApisOwnMessage_WhenItFails()
    {
        var client = ClientReturning(HttpStatusCode.Forbidden, JsonContent.Create(new { error = "Admins only." }));

        var unlink = async () => await client.UnlinkReferenceAsync("abc", TestContext.Current.CancellationToken);

        (await unlink.Should().ThrowAsync<ApiRequestException>()).Which.Message.Should().Be("Admins only.");
    }

    [Theory]
    [InlineData("get")]
    [InlineData("update")]
    [InlineData("delete")]
    [InlineData("refresh")]
    [InlineData("unlink")]
    public async Task EveryItemCall_KeepsTheIdInsideItsOwnPathSegment(string call)
    {
        // an id comes from the page route, so an unescaped "../admin" would address another API resource
        var handler = new RecordingHandler();
        var client = new MovieApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.example") });
        var ct = TestContext.Current.CancellationToken;
        const string Id = "../admin";

        switch (call)
        {
            case "get": await client.GetOneAsync(Id, ct); break;
            case "update": await client.UpdateAsync(new MovieDto { Id = Id, Title = "Heat" }, ct); break;
            case "delete": await client.DeleteAsync(Id, ct); break;
            case "refresh": await client.RefreshReferenceAsync(Id, ct); break;
            case "unlink": await client.UnlinkReferenceAsync(Id, ct); break;
        }

        handler.RequestUri!.AbsolutePath.Should().StartWith("/api/movies/..%2Fadmin");
    }
}
