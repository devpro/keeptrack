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
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The sample responses below are trimmed but otherwise verbatim in shape from the real Discogs API,
/// including the noise this client exists to filter: <c>q=</c> is free text over the artist name, label,
/// credits and tracklist, so a search returns ordinary-looking hits whose release title never contained the
/// searched words at all.
/// </summary>
[Trait("Category", "UnitTests")]
public class DiscogsClientTest
{
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.Query);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(respond(request), Encoding.UTF8, "application/json")
            });
        }
    }

    private static (DiscogsClient Client, StubHttpMessageHandler Handler) BuildClient(Func<HttpRequestMessage, string> respond)
    {
        var handler = new StubHttpMessageHandler(respond);
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.discogs.com/") };
        return (new DiscogsClient(http, new DiscogsSettings { Token = "test-token" }), handler);
    }

    /// <summary>Discogs titles a search hit "Artist - Album Title" rather than exposing the two separately.</summary>
    private static string SearchResponse(params (int Id, string CombinedTitle, int? Year)[] results) =>
        $$"""
        {
          "results": [
            {{string.Join(",\n", results.Select(r => $$"""
            { "id": {{r.Id}}, "title": "{{r.CombinedTitle}}", "year": {{(r.Year is null ? "null" : r.Year.ToString())}}, "cover_image": "https://img.discogs.com/{{r.Id}}.jpg" }
            """))}}
          ]
        }
        """;

    [Fact]
    public async Task SearchAlbumsAsync_DiscardsResultsWhoseReleaseTitleNeverMatchedTheSearchedTitle()
    {
        // verbatim from the real API for q=Discovery&artist=Daft Punk: the last two are genuine Daft Punk
        // releases that free-text matched on something other than their title
        var (client, _) = BuildClient(_ => SearchResponse(
            (1, "Daft Punk - Discovery", 2001),
            (2, "Daft Punk - Homework / Discovery", 2001),
            (3, "Daft Punk - Live @ Rex Club, Paris", 1997),
            (4, "Daft Punk - MP3 Collection", 2005)));

        var results = await client.SearchAlbumsAsync("Discovery", null, "Daft Punk", TestContext.Current.CancellationToken);

        results.Select(r => r.Title).Should().Equal("Discovery", "Homework / Discovery");
    }

    [Fact]
    public async Task SearchAlbumsAsync_DiscardsAResultWhoseOnlyMatchWasTheArtistName()
    {
        // q=Sabbath against the real API: "Paranoid" is only a hit because the artist is "Black Sabbath"
        var (client, _) = BuildClient(_ => SearchResponse(
            (1, "Black Sabbath - Sabbath Bloody Sabbath", 1973),
            (2, "Black Sabbath - Paranoid", 1970)));

        var results = await client.SearchAlbumsAsync("Sabbath", null, cancellationToken: TestContext.Current.CancellationToken);

        results.Should().ContainSingle();
        results[0].Title.Should().Be("Sabbath Bloody Sabbath");
        results[0].Artist.Should().Be("Black Sabbath");
    }

    [Fact]
    public async Task SearchAlbumsAsync_KeepsEditionsAndCompilationsThatDoCarryTheSearchedTitle()
    {
        var (client, _) = BuildClient(_ => SearchResponse(
            (1, "Nirvana - Nevermind", 1991),
            (2, "Nirvana - Nevermind (Demo & Outtakes)", null),
            (3, "Nirvana - Nevermind, It's An Interview", 1992)));

        var results = await client.SearchAlbumsAsync("Nevermind", null, "Nirvana", TestContext.Current.CancellationToken);

        results.Should().HaveCount(3);
    }

    /// <summary>
    /// The pre-existing widening step - see the comment in <c>SearchAlbumsAsync</c> - now also covers a
    /// response whose every hit fails the title check, which for this purpose is the same as no response.
    /// </summary>
    [Fact]
    public async Task SearchAlbumsAsync_RetriesWithoutTheArtist_WhenNothingTheArtistQueryReturnedIsActuallyTitledThat()
    {
        var (client, handler) = BuildClient(request => request.RequestUri!.Query.Contains("artist=", StringComparison.Ordinal)
            // Discogs' own artist index matched, but on none of these releases' titles
            ? SearchResponse((1, "BLACKPINK - The Album", 2020), (2, "BLACKPINK - Kill This Love", 2019))
            : SearchResponse((3, "BLACKPINK - Born Pink", 2022)));

        var results = await client.SearchAlbumsAsync("Born Pink", null, "BLACKPINK", TestContext.Current.CancellationToken);

        results.Should().ContainSingle();
        results[0].Title.Should().Be("Born Pink");
        handler.Requests.Should().HaveCount(2);
        handler.Requests[1].Should().NotContain("artist=");
    }

    [Fact]
    public async Task SearchAlbumsAsync_ReturnsNothing_WhenNoCandidateCarriesTheSearchedTitle()
    {
        var (client, _) = BuildClient(_ => SearchResponse((1, "Black Sabbath - Paranoid", 1970)));

        var results = await client.SearchAlbumsAsync("Sabbath", null, cancellationToken: TestContext.Current.CancellationToken);

        results.Should().BeEmpty();
    }
}
