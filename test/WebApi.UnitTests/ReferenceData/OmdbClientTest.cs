using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// OMDb's rating/vote fields are strings ("8.7", "1,950,000", or "N/A") and it signals an unknown id via
/// <c>Response:"False"</c> - this pins the parsing of each of those shapes plus the graceful no-op when no
/// key is configured (IMDb enrichment is optional, so movies/TV must keep working without an OMDb key).
/// </summary>
[Trait("Category", "UnitTests")]
public class OmdbClientTest
{
    private static OmdbClient BuildClient(string? apiKey, Func<HttpResponseMessage>? respond = null)
    {
        var handler = new StubHttpMessageHandler(respond ?? (() => new HttpResponseMessage(HttpStatusCode.OK)));
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://www.omdbapi.com/") };
        return new OmdbClient(http, new OmdbSettings { ApiKey = apiKey });
    }

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK)
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

    [Fact]
    public async Task GetRatingAsync_ParsesTheRatingAndCommaSeparatedVoteCount()
    {
        var client = BuildClient("k", () => Json("""{"imdbRating":"8.7","imdbVotes":"1,950,000","Response":"True"}"""));

        var rating = await client.GetRatingAsync("tt0133093", TestContext.Current.CancellationToken);

        rating.Should().NotBeNull();
        rating!.Value.Should().Be(8.7);
        rating.Count.Should().Be(1_950_000);
    }

    [Fact]
    public async Task GetRatingAsync_ReturnsNull_WhenTheTitleHasNoRatingYet()
    {
        var client = BuildClient("k", () => Json("""{"imdbRating":"N/A","imdbVotes":"N/A","Response":"True"}"""));

        var rating = await client.GetRatingAsync("tt0133093", TestContext.Current.CancellationToken);

        rating.Should().BeNull();
    }

    [Fact]
    public async Task GetRatingAsync_ReturnsNull_WhenTheIdIsUnknownToOmdb()
    {
        var client = BuildClient("k", () => Json("""{"Response":"False","Error":"Incorrect IMDb ID."}"""));

        var rating = await client.GetRatingAsync("tt0000000", TestContext.Current.CancellationToken);

        rating.Should().BeNull();
    }

    [Fact]
    public async Task GetRatingAsync_DoesNotCallTheProvider_WhenNoApiKeyIsConfigured()
    {
        var handler = new StubHttpMessageHandler(() => Json("""{"imdbRating":"8.7","imdbVotes":"1","Response":"True"}"""));
        var client = new OmdbClient(new HttpClient(handler) { BaseAddress = new Uri("https://www.omdbapi.com/") }, new OmdbSettings { ApiKey = null });

        var rating = await client.GetRatingAsync("tt0133093", TestContext.Current.CancellationToken);

        rating.Should().BeNull();
        handler.CallCount.Should().Be(0);
    }
}
