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
/// <see cref="OpenLibraryClient.GetBookDetailsAsync"/> reads the year out of <c>first_publish_date</c>, a bare year ("1954") or a full date ("November 12, 1972").
/// Taking the first four digits would read the day and the year's start ("12" and "19", so 1219), as on the real API's "The Fellowship of the Ring" (OL27513W).
/// </summary>
[Trait("Category", "UnitTests")]
public class OpenLibraryClientTest
{
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(respond(request), Encoding.UTF8, "application/json")
            });
    }

    private static OpenLibraryClient BuildClient(Func<HttpRequestMessage, string> respond)
    {
        var http = new HttpClient(new StubHttpMessageHandler(respond)) { BaseAddress = new Uri("https://openlibrary.org/") };
        return new OpenLibraryClient(http);
    }

    [Fact]
    public void ProviderKey_IsOpenLibrary()
    {
        BuildClient(_ => "").ProviderKey.Should().Be("openlibrary");
    }

    [Fact]
    public async Task GetBookDetailsAsync_ParsesTheYearFromAMonthDayYearPublishDate()
    {
        var client = BuildClient(_ => """{"title":"The Fellowship of the Ring","first_publish_date":"November 12, 1972","authors":[]}""");

        var details = await client.GetBookDetailsAsync("/works/OL27513W", TestContext.Current.CancellationToken);

        details!.Year.Should().Be(1972);
    }

    [Fact]
    public async Task GetBookDetailsAsync_ParsesTheYearFromABareYearPublishDate()
    {
        var client = BuildClient(_ => """{"title":"The Lord of the Rings","first_publish_date":"1954","authors":[]}""");

        var details = await client.GetBookDetailsAsync("/works/OL27448W", TestContext.Current.CancellationToken);

        details!.Year.Should().Be(1954);
    }

    /// <summary>
    /// This client searches by ISBN, so an ISBN search has a fallback when Google Books is down (a total <c>volumes?q=</c> outage).
    /// The response below is the real API's answer for 9782265002104.
    /// </summary>
    [Fact]
    public async Task SearchBooksAsync_SearchesTheIndexByIsbn_WhenAnIsbnIsSupplied()
    {
        string? capturedQuery = null;
        var client = BuildClient(request =>
        {
            capturedQuery = Uri.UnescapeDataString(request.RequestUri!.Query);
            return """
                {"docs":[{"key":"/works/OL19837814W","title":"La trilogie des héros de Phlan, la fontaine de pénombre",
                "first_publish_year":1994,"author_name":["James M. Ward","Anne K. Brown"],"cover_i":8632965}]}
                """;
        });

        var results = await client.SearchBooksAsync("Ignored Title", null, "Ignored Author", "9782265002104", TestContext.Current.CancellationToken);

        capturedQuery.Should().Contain("q=isbn:9782265002104").And.NotContain("author=");
        var result = results.Should().ContainSingle().Subject;
        result.ExternalId.Should().Be("/works/OL19837814W");
        result.Year.Should().Be(1994);
        result.Author.Should().Be("James M. Ward");
        result.ImageUrl.Should().Be("https://covers.openlibrary.org/b/id/8632965-L.jpg");
    }

    /// <summary>
    /// A doc with no title is labelled with the searched text on the title path, but an ISBN search has no such text, an id not being a title.
    /// A titleless stub is then dropped rather than surfaced as a candidate named after a number.
    /// </summary>
    [Fact]
    public async Task SearchBooksAsync_DropsATitlelessMatch_OnTheIsbnPath()
    {
        var client = BuildClient(_ => """{"docs":[{"key":"/works/OL1W"},{"key":"/works/OL2W","title":"A Real Title"}]}""");

        var results = await client.SearchBooksAsync("Ignored", null, null, "9782265002104", TestContext.Current.CancellationToken);

        results.Should().ContainSingle().Which.Title.Should().Be("A Real Title");
    }
}
