using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Shared;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>
/// The client half of surfacing a provider outage honestly. <c>EnsureSuccessStatusCode</c> throws with only
/// the status line and discards the body, so the <c>{ error }</c> the API deliberately writes never reached a
/// user - every upstream failure showed up as an unexplained "502 (Bad Gateway)".
/// </summary>
[Trait("Category", "UnitTests")]
public class ApiResponseExtensionsTest
{
    private static HttpResponseMessage Response(HttpStatusCode status, string? json = null) =>
        new(status)
        {
            Content = json is null
                ? new StringContent("", Encoding.UTF8, "application/json")
                : new StringContent(json, Encoding.UTF8, "application/json")
        };

    [Fact]
    public async Task EnsureSuccessOrThrowAsync_DoesNothing_OnASuccessfulResponse()
    {
        var act = async () => await Response(HttpStatusCode.OK, "{}").EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task EnsureSuccessOrThrowAsync_ThrowsTheApisOwnMessage_RatherThanTheStatusLine()
    {
        var response = Response(HttpStatusCode.BadGateway, """{"error":"The external provider returned 503 (ServiceUnavailable)."}""");

        var act = async () => await response.EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        var thrown = await act.Should().ThrowAsync<ApiRequestException>();
        thrown.Which.Message.Should().Be("The external provider returned 503 (ServiceUnavailable).");
        thrown.Which.StatusCode.Should().Be(HttpStatusCode.BadGateway);
    }

    /// <summary>
    /// 502 is what tells a caller the failure was upstream rather than in this API, which is what decides
    /// whether reaching for a different provider is worth suggesting.
    /// </summary>
    [Fact]
    public async Task ApiRequestException_MarksA502AsAnUpstreamProviderFailure()
    {
        var act = async () => await Response(HttpStatusCode.BadGateway, """{"error":"upstream"}""").EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ApiRequestException>()).Which.IsUpstreamProviderFailure.Should().BeTrue();
    }

    [Fact]
    public async Task ApiRequestException_DoesNotMarkANonGatewayFailureAsUpstream()
    {
        var act = async () => await Response(HttpStatusCode.InternalServerError, """{"error":"our own bug"}""").EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ApiRequestException>()).Which.IsUpstreamProviderFailure.Should().BeFalse();
    }

    /// <summary>
    /// A failure while reading the explanation of a failure must never replace it with an exception of its
    /// own - a proxy's HTML error page in front of the API is the realistic case.
    /// </summary>
    [Fact]
    public async Task EnsureSuccessOrThrowAsync_FallsBackToTheStatusLine_WhenTheBodyIsNotTheExpectedJson()
    {
        var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
        {
            Content = new StringContent("<html><body>503 Service Unavailable</body></html>", Encoding.UTF8, "text/html")
        };

        var act = async () => await response.EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ApiRequestException>()).Which.Message.Should().Contain("503");
    }

    [Fact]
    public async Task EnsureSuccessOrThrowAsync_FallsBackToTheStatusLine_WhenThereIsNoBodyAtAll()
    {
        var act = async () => await Response(HttpStatusCode.BadGateway).EnsureSuccessOrThrowAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ApiRequestException>()).Which.Message.Should().Contain("502");
    }

    [Fact]
    public async Task ReadJsonOrThrowAsync_ReturnsTheDeserializedBody_OnSuccess()
    {
        var response = Response(HttpStatusCode.OK, """[{"externalId":"id1"}]""");

        var results = await response.ReadJsonOrThrowAsync<System.Collections.Generic.List<SearchHit>>(TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.ExternalId.Should().Be("id1");
    }

    private sealed class SearchHit
    {
        public string? ExternalId { get; set; }
    }
}
