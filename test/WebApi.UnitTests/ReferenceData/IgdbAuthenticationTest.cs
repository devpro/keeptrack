using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// IGDB is the one provider that authenticates with a token rather than an api key, so the two pieces that
/// token brings with it get their own coverage: the cache in front of Twitch, and the handler that attaches it
/// and recovers from a rejection. Neither can be exercised through the client's own tests, and getting either
/// wrong is silent - an over-eager cache fetches on every call, a missing 401 retry breaks every IGDB request
/// until the process restarts.
/// </summary>
[Trait("Category", "UnitTests")]
public class IgdbAuthenticationTest
{
    [Fact]
    public async Task GetTokenAsync_ReturnsNull_AndNeverCallsTwitch_WhenIgdbIsNotConfigured()
    {
        // a deployment with no credentials must degrade to "no video game reference data", not fail to boot
        // or hammer Twitch with unauthenticated requests
        var handler = new StubHandler(_ => TokenResponse("t1", 3600));
        var provider = CreateProvider(handler, new IgdbSettings());

        var token = await provider.GetTokenAsync(TestContext.Current.CancellationToken);

        token.Should().BeNull();
        handler.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task GetTokenAsync_FetchesOnce_AndServesEveryLaterCallFromTheCache()
    {
        var handler = new StubHandler(_ => TokenResponse("t1", 3600));
        var provider = CreateProvider(handler);

        var first = await provider.GetTokenAsync(TestContext.Current.CancellationToken);
        var second = await provider.GetTokenAsync(TestContext.Current.CancellationToken);

        first.Should().Be("t1");
        second.Should().Be("t1");
        handler.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_FetchesConcurrentCallersToken_ExactlyOnce()
    {
        // the cold-start case: a burst of requests must not each start their own token exchange
        var handler = new StubHandler(_ => TokenResponse("t1", 3600));
        var provider = CreateProvider(handler);

        var tokens = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => provider.GetTokenAsync(TestContext.Current.CancellationToken)));

        tokens.Should().AllBe("t1");
        handler.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task GetTokenAsync_FetchesAgain_AfterInvalidate()
    {
        var handler = new StubHandler(call => TokenResponse($"t{call}", 3600));
        var provider = CreateProvider(handler);

        await provider.GetTokenAsync(TestContext.Current.CancellationToken);
        provider.Invalidate();
        var refreshed = await provider.GetTokenAsync(TestContext.Current.CancellationToken);

        refreshed.Should().Be("t2");
        handler.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_FetchesAgain_WhenTheCachedTokenIsAlreadyPastItsRenewalPoint()
    {
        // an already-expired token must never be served from the cache. The renewal margin is capped at half
        // the token's lifetime for the same reason in reverse: a fixed margin longer than the lifetime would
        // make *every* token look expired on arrival and turn the cache into an extra round trip per call.
        var handler = new StubHandler(call => TokenResponse($"t{call}", 0));
        var provider = CreateProvider(handler);

        await provider.GetTokenAsync(TestContext.Current.CancellationToken);
        var second = await provider.GetTokenAsync(TestContext.Current.CancellationToken);

        second.Should().Be("t2");
        handler.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task GetTokenAsync_ReturnsNull_WhenTwitchRejectsTheCredentials()
    {
        // never throws: a bad or expired secret must surface as "IGDB is unavailable", not as a 500 from an
        // admin search
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var provider = CreateProvider(handler);

        var token = await provider.GetTokenAsync(TestContext.Current.CancellationToken);

        token.Should().BeNull();
    }

    [Fact]
    public async Task AuthenticationHandler_AttachesTheClientIdAndBearerToken()
    {
        var tokenProvider = new FakeTokenProvider("t1");
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = CreateAuthenticatedClient(tokenProvider, handler);

        await client.PostAsync("games", new StringContent("fields name;", Encoding.UTF8, "text/plain"), TestContext.Current.CancellationToken);

        handler.Requests.Should().ContainSingle();
        handler.Requests[0].ClientId.Should().Be("client-1");
        handler.Requests[0].Authorization.Should().Be("Bearer t1");
    }

    [Fact]
    public async Task AuthenticationHandler_RefreshesAndRetriesOnce_WhenIgdbRejectsTheToken()
    {
        // a revoked or early-expired token would otherwise fail every request until the process restarted,
        // since nothing else ever invalidates the cache
        var tokenProvider = new FakeTokenProvider("t1", "t2");
        var handler = new StubHandler(call => new HttpResponseMessage(call == 1 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        var client = CreateAuthenticatedClient(tokenProvider, handler);

        var response = await client.PostAsync("games", new StringContent("fields name;", Encoding.UTF8, "text/plain"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        tokenProvider.InvalidateCount.Should().Be(1);
        handler.Requests.Select(r => r.Authorization).Should().Equal("Bearer t1", "Bearer t2");
        // the retry carries the same body - a request whose content was consumed by the first attempt would
        // otherwise reach IGDB empty and come back as a query error rather than a result
        handler.Requests.Select(r => r.Body).Should().Equal("fields name;", "fields name;");
    }

    [Fact]
    public async Task AuthenticationHandler_DoesNotRetryASecondTime_WhenTheFreshTokenIsAlsoRejected()
    {
        // a second 401 means the credentials themselves are wrong, which retrying cannot fix
        var tokenProvider = new FakeTokenProvider("t1", "t2");
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        var client = CreateAuthenticatedClient(tokenProvider, handler);

        var response = await client.PostAsync("games", new StringContent("fields name;", Encoding.UTF8, "text/plain"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        handler.CallCount.Should().Be(2);
    }

    [Fact]
    public async Task AuthenticationHandler_NeverSendsARequest_WhenThereIsNoTokenToSend()
    {
        var tokenProvider = new FakeTokenProvider();
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = CreateAuthenticatedClient(tokenProvider, handler);

        var response = await client.PostAsync("games", new StringContent("fields name;", Encoding.UTF8, "text/plain"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        handler.CallCount.Should().Be(0);
    }

    private static IgdbTokenProvider CreateProvider(StubHandler handler, IgdbSettings? settings = null)
    {
        var services = new ServiceCollection();
        services.AddHttpClient(IgdbTokenProvider.TokenHttpClientName, client => client.BaseAddress = new Uri("https://id.twitch.test/"))
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        var factory = services.BuildServiceProvider().GetRequiredService<IHttpClientFactory>();

        return new IgdbTokenProvider(
            factory,
            settings ?? new IgdbSettings { ClientId = "client-1", ClientSecret = "secret-1" },
            NullLogger<IgdbTokenProvider>.Instance);
    }

    private static HttpClient CreateAuthenticatedClient(IIgdbTokenProvider tokenProvider, StubHandler handler) =>
        new(new IgdbAuthenticationHandler(tokenProvider) { InnerHandler = handler }) { BaseAddress = new Uri("https://api.igdb.test/") };

    private static HttpResponseMessage TokenResponse(string token, int expiresInSeconds) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""{"access_token":"{{token}}","expires_in":{{expiresInSeconds}},"token_type":"bearer"}""", Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<int, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        public List<(string? ClientId, string? Authorization, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            Requests.Add((
                request.Headers.TryGetValues("Client-ID", out var clientId) ? string.Join(",", clientId) : null,
                request.Headers.Authorization?.ToString(),
                request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken)));
            return respond(CallCount);
        }
    }

    /// <summary>Hands out the given tokens in order, then keeps returning the last one (or null if there were none).</summary>
    private sealed class FakeTokenProvider(params string[] tokens) : IIgdbTokenProvider
    {
        private int _index;

        public string? ClientId => "client-1";

        public int InvalidateCount { get; private set; }

        public Task<string?> GetTokenAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(tokens.Length == 0 ? null : tokens[Math.Min(_index, tokens.Length - 1)]);

        public void Invalidate()
        {
            InvalidateCount++;
            _index++;
        }
    }
}
