using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Polly;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Exercises the same <c>AddStandardResilienceHandler()</c> wiring Program.cs applies to every external
/// provider client (TMDB/RAWG/Open Library/Discogs) - tested once here against <see cref="RawgClient"/> as
/// a representative example, since the wiring is identical for all four and duplicating this per-provider
/// would just be the same test four times over. Confirms the actual regression this handler guards against:
/// a transient failure from the external provider is retried and recovered rather than surfacing to the
/// caller, and a provider that stays down fails cleanly (a normal exception, mapped to a JSON 500 by
/// <see cref="Keeptrack.WebApi.Filters.ApiExceptionFilterAttribute"/>) instead of hanging indefinitely.
/// </summary>
[Trait("Category", "UnitTests")]
public class ExternalProviderResilienceTest
{
    private static IRawgClient BuildClient(HttpMessageHandler primaryHandler, Action<Microsoft.Extensions.Http.Resilience.HttpStandardResilienceOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(new RawgSettings { ApiKey = "test-key" });
        services.AddHttpClient<IRawgClient, RawgClient>(client => client.BaseAddress = new Uri("https://example.test/"))
            .ConfigurePrimaryHttpMessageHandler(() => primaryHandler)
            .AddStandardResilienceHandler(options =>
            {
                // shortened so the test runs fast and deterministically - same strategies as production
                // (retry, attempt timeout, total timeout, circuit breaker), just faster delays.
                options.Retry.MaxRetryAttempts = 3;
                options.Retry.Delay = TimeSpan.FromMilliseconds(1);
                options.Retry.BackoffType = DelayBackoffType.Constant;
                options.Retry.UseJitter = false;
                options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(2);
                options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(4);
                options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(5);
                configure?.Invoke(options);
            });

        return services.BuildServiceProvider().GetRequiredService<IRawgClient>();
    }

    private sealed class StubHttpMessageHandler(Func<int, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(respond(CallCount));
        }
    }

    private static HttpResponseMessage SuccessResponse() => new(HttpStatusCode.OK)
    {
        Content = new StringContent(
            """{"results":[{"id":1,"name":"Nioh 3","released":"2026-03-01","background_image":null}]}""",
            Encoding.UTF8, "application/json")
    };

    [Fact]
    public async Task StandardResilienceHandler_RetriesATransientFailureAndRecovers()
    {
        var handler = new StubHttpMessageHandler(callCount =>
            callCount < 3 ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) : SuccessResponse());
        var client = BuildClient(handler);

        var results = await client.SearchGamesAsync("Nioh 3", null, TestContext.Current.CancellationToken);

        results.Should().ContainSingle(r => r.Title == "Nioh 3");
        handler.CallCount.Should().Be(3);
    }

    [Fact]
    public async Task StandardResilienceHandler_FailsCleanlyInsteadOfHangingWhenTheProviderStaysDown()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        var client = BuildClient(handler);

        var act = async () => await client.SearchGamesAsync("Nioh 3", null);

        await act.Should().ThrowAsync<HttpRequestException>();
        handler.CallCount.Should().Be(4); // 1 initial attempt + 3 retries, then it gives up
    }
}
