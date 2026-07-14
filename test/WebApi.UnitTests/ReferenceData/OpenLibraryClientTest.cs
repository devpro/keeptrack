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
/// <see cref="OpenLibraryClient.GetBookDetailsAsync"/>'s year parsing used to strip all digits out of
/// <c>first_publish_date</c> and take the first 4 - correct for a bare year ("1954") but wrong whenever the
/// date includes a day-of-month before the year ("November 12, 1972"), where it read the day's digits
/// followed by the year's leading digits ("12" + "19" -> 1219) instead of the actual year. Confirmed against
/// the real API for Tolkien's "The Fellowship of the Ring" (OL27513W), whose real
/// <c>first_publish_date</c> is "November 12, 1972".
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

    private static IBookReferenceClient BuildClient(Func<HttpRequestMessage, string> respond)
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
}
