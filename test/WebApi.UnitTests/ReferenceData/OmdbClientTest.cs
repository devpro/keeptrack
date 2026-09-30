using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// OMDb's rating/vote fields are strings ("8.7", "1,950,000", or "N/A") and it signals an unknown id via
/// <c>Response:"False"</c> - this pins the parsing of each of those shapes plus the graceful no-op when no
/// key is configured (IMDb enrichment is optional, so movies/TV must keep working without an OMDb key).
/// <para>
/// It also pins the two behaviours the hard 1000/day free tier forces: every call is reserved against the
/// shared budget first, and *nothing* the provider or the network does escapes as an exception - an
/// exhausted key answers 401, which used to surface as a 500 from admin manual linking and Explore "add".
/// The <see cref="OmdbLookupResult.Attempted"/> flag is asserted throughout, because callers use it to
/// decide whether a title may be written off as "OMDb has nothing for this".
/// </para>
/// </summary>
[Trait("Category", "UnitTests")]
public class OmdbClientTest
{
    private readonly FakeOmdbCallBudget _budget = new();

    private OmdbClient BuildClient(string? apiKey, Func<HttpResponseMessage>? respond = null)
    {
        var handler = new StubHttpMessageHandler(respond ?? (() => new HttpResponseMessage(HttpStatusCode.OK)));
        return BuildClient(apiKey, handler);
    }

    private OmdbClient BuildClient(string? apiKey, HttpMessageHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://www.omdbapi.com/") };
        return new OmdbClient(http, new OmdbSettings { ApiKey = apiKey }, _budget, NullLogger<OmdbClient>.Instance);
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private sealed class StubHttpMessageHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(respond());
        }
    }

    private sealed class ThrowingHttpMessageHandler(Func<Exception> throws) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw throws();
    }

    [Fact]
    public async Task GetRatingAsync_ParsesTheRatingAndCommaSeparatedVoteCount()
    {
        var client = BuildClient("k", () => Json("""{"imdbRating":"8.7","imdbVotes":"1,950,000","Response":"True"}"""));

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeTrue();
        lookup.Rating.Should().NotBeNull();
        lookup.Rating!.Value.Should().Be(8.7);
        lookup.Rating.Count.Should().Be(1_950_000);
    }

    [Fact]
    public async Task GetRatingAsync_ReturnsAnAttemptedEmptyResult_WhenTheTitleHasNoRatingYet()
    {
        var client = BuildClient("k", () => Json("""{"imdbRating":"N/A","imdbVotes":"N/A","Response":"True"}"""));

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        // OMDb answered - the caller may record that and stop asking about this title for a while
        lookup.Attempted.Should().BeTrue();
        lookup.Rating.Should().BeNull();
    }

    [Fact]
    public async Task GetRatingAsync_ReturnsAnAttemptedEmptyResult_WhenTheIdIsUnknownToOmdb()
    {
        var client = BuildClient("k", () => Json("""{"Response":"False","Error":"Incorrect IMDb ID."}"""));

        var lookup = await client.GetRatingAsync("tt0000000", OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeTrue();
        lookup.Rating.Should().BeNull();
        _budget.LimitReported.Should().BeFalse(); // a bad id says nothing about the key's allowance
    }

    [Fact]
    public async Task GetRatingAsync_DoesNotCallTheProvider_WhenNoApiKeyIsConfigured()
    {
        var handler = new StubHttpMessageHandler(() => Json("""{"imdbRating":"8.7","imdbVotes":"1","Response":"True"}"""));
        var client = BuildClient(apiKey: null, handler);

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeFalse();
        lookup.Rating.Should().BeNull();
        handler.CallCount.Should().Be(0);
        _budget.Reserved.Should().Be(0); // and no budget is spent on a call that never happens
    }

    [Fact]
    public async Task GetRatingAsync_DoesNotCallTheProvider_WhenTheDailyBudgetIsSpent()
    {
        var handler = new StubHttpMessageHandler(() => Json("""{"imdbRating":"8.7","imdbVotes":"1","Response":"True"}"""));
        var client = BuildClient("k", handler);
        _budget.Exhausted = true;

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        // not attempted, so the caller must not write this title off as "OMDb has no rating for it"
        lookup.Attempted.Should().BeFalse();
        handler.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task GetRatingAsync_ReservesOneCallFromTheBudget_PerLookup()
    {
        var client = BuildClient("k", () => Json("""{"imdbRating":"8.7","imdbVotes":"1","Response":"True"}"""));

        await client.GetRatingAsync("tt1", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);
        await client.GetRatingAsync("tt2", OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        _budget.Reserved.Should().Be(2);
    }

    [Fact]
    public async Task GetRatingAsync_StopsTheDay_WhenOmdbReportsTheRequestLimitReached()
    {
        // the real over-quota answer: 401 with a JSON body, which GetFromJsonAsync would have thrown for
        var handler = new StubHttpMessageHandler(() => Json("""{"Response":"False","Error":"Request limit reached!"}""", HttpStatusCode.Unauthorized));
        var client = BuildClient("k", handler);

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Background, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeFalse();
        _budget.LimitReported.Should().BeTrue();
        // and the next lookup doesn't even reach the provider, instead of firing hundreds more doomed calls
        (await client.GetRatingAsync("tt2", OmdbCallPriority.Background, TestContext.Current.CancellationToken)).Attempted.Should().BeFalse();
        handler.CallCount.Should().Be(1);
    }

    [Fact]
    public async Task GetRatingAsync_StopsTheDay_WhenOmdbRejectsTheApiKey()
    {
        // an unusable key can't be retried into working either - one log, then stop, rather than one failure per item
        var client = BuildClient("k", () => Json("""{"Response":"False","Error":"Invalid API key!"}""", HttpStatusCode.Unauthorized));

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeFalse();
        _budget.LimitReported.Should().BeTrue();
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task GetRatingAsync_ReturnsNotAttempted_OnAnErrorStatus_WithoutThrowing(HttpStatusCode status)
    {
        var client = BuildClient("k", () => Json("""{"Response":"False"}""", status));

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeFalse();
        _budget.LimitReported.Should().BeFalse(); // a transient failure must not write off the whole day
    }

    public static TheoryData<Exception> TransportFailures() =>
    [
        new HttpRequestException("connection refused"),
        new TaskCanceledException("the request timed out"),
        new JsonException("unexpected token")
    ];

    [Theory]
    [MemberData(nameof(TransportFailures))]
    public async Task GetRatingAsync_ReturnsNotAttempted_OnATransportFailure_WithoutThrowing(Exception failure)
    {
        // IMDb is best-effort: an admin's manual link and a user's Explore "add" both await this, and neither
        // may fail because OMDb was unreachable
        var client = BuildClient("k", new ThrowingHttpMessageHandler(() => failure));

        var lookup = await client.GetRatingAsync("tt0133093", OmdbCallPriority.Interactive, TestContext.Current.CancellationToken);

        lookup.Attempted.Should().BeFalse();
        lookup.Rating.Should().BeNull();
    }

    [Fact]
    public async Task GetRatingAsync_PropagatesTheCallersOwnCancellation()
    {
        // a timeout is swallowed, but the caller giving up is not - a shutting-down background service must
        // not look like it completed its work
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var client = BuildClient("k", new ThrowingHttpMessageHandler(() => new TaskCanceledException("cancelled")));

        var act = () => client.GetRatingAsync("tt0133093", OmdbCallPriority.Background, cancelled.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
