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

[Trait("Category", "UnitTests")]
public class GoogleBooksClientTest
{
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(respond(request), Encoding.UTF8, "application/json")
            });
    }

    private static GoogleBooksClient BuildClient(Func<HttpRequestMessage, string> respond)
    {
        var http = new HttpClient(new StubHttpMessageHandler(respond)) { BaseAddress = new Uri("https://www.googleapis.com/books/v1/") };
        return new GoogleBooksClient(http, new GoogleBooksSettings { ApiKey = "test-key" });
    }

    [Fact]
    public void ProviderKey_IsGoogleBooks() => BuildClient(_ => "").ProviderKey.Should().Be("googlebooks");

    [Fact]
    public void DisplayName_IsGoogleBooks() => BuildClient(_ => "").DisplayName.Should().Be("Google Books");

    [Fact]
    public async Task GetBookDetailsAsync_KeepsBoldItalicAndBreakFormattingInTheDescriptionAndUpgradesTheThumbnailToHttps()
    {
        var client = BuildClient(_ => """
            {
              "id": "abc123",
              "volumeInfo": {
                "title": "Killing Floor",
                "authors": ["Lee Child"],
                "publishedDate": "1997-03-01",
                "description": "A <b>gripping</b> thriller.<br>The first Jack Reacher novel.",
                "categories": ["Fiction / Thrillers"],
                "language": "en",
                "imageLinks": { "thumbnail": "http://books.google.com/books/content?id=abc123&printsec=frontcover" }
              }
            }
            """);

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details!.Title.Should().Be("Killing Floor");
        details.Year.Should().Be(1997);
        details.Author.Should().Be("Lee Child");
        details.Language.Should().Be("en");
        details.Synopsis.Should().Be("A <b>gripping</b> thriller.<br/>The first Jack Reacher novel.");
        details.ImageUrl.Should().StartWith("https://");
        details.Genres.Should().ContainSingle().Which.Should().Be("Fiction / Thrillers");
    }

    [Fact]
    public async Task GetBookDetailsAsync_ConvertsPlainNewlinesToBreakTags()
    {
        // In real descriptions paragraph breaks are sometimes plain "\n", not <br>, and HTML collapses bare newlines,
        // so a description with only bold and italic markup would render as one undivided paragraph.
        var client = BuildClient(_ => """{"id":"abc123","volumeInfo":{"title":"The Hobbit","description":"Bilbo Baggins is a hobbit.\r\n\r\nA wizard visits."}}""");

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details!.Synopsis.Should().Be("Bilbo Baggins is a hobbit.<br/><br/>A wizard visits.");
    }

    [Fact]
    public async Task GetBookDetailsAsync_StripsAnyTagOutsideTheBoldItalicBreakAllowlist_IncludingAttributesOnAllowedTags()
    {
        // The fixed allowlist-and-reconstruct approach, not a general sanitizer, makes the result safe as a MarkupString.
        // An attribute on an allowed tag (an injection vector such as onclick or onmouseover) never survives, nor does any other tag or script.
        var client = BuildClient(_ => """
            {
              "id": "abc123",
              "volumeInfo": {
                "title": "Killing Floor",
                "description": "<script>alert(1)</script><b onclick=\"alert(2)\">bold</b><p class=\"x\">para</p>"
              }
            }
            """);

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        // The <script> and <p> tags are removed by tag stripping, not an HTML parser, so text between them (the script's "alert(1)" body) survives as inert plain text.
        // No tag survives, so nothing can execute.
        details!.Synopsis.Should().Be("alert(1)<b>bold</b>para");
    }

    [Fact]
    public async Task GetBookDetailsAsync_DecodesEntitiesBeforeStrippingTags_SoAnEncodedTagCannotSurvive()
    {
        // if entities were decoded AFTER stripping,
        // an entity-encoded "<script>" (harmless text at that point) would decode into a live tag only after the safety filter already ran
        var client = BuildClient(_ => """{"id":"abc123","volumeInfo":{"title":"Killing Floor","description":"&lt;script&gt;alert(1)&lt;/script&gt; caf&eacute;"}}""");

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details!.Synopsis.Should().Be("alert(1) café");
    }

    [Fact]
    public async Task GetBookDetailsAsync_PrefersIsbn13OverIsbn10_WhenBothArePresent()
    {
        var client = BuildClient(_ => """
            {
              "id": "abc123",
              "volumeInfo": {
                "title": "Killing Floor",
                "industryIdentifiers": [
                  { "type": "ISBN_10", "identifier": "0399142032" },
                  { "type": "ISBN_13", "identifier": "9780399142034" }
                ]
              }
            }
            """);

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details!.Isbn.Should().Be("9780399142034");
    }

    [Fact]
    public async Task GetBookDetailsAsync_FallsBackToIsbn10_WhenNoIsbn13IsPresent()
    {
        var client = BuildClient(_ => """{"id":"abc123","volumeInfo":{"title":"Killing Floor","industryIdentifiers":[{"type":"ISBN_10","identifier":"0399142032"}]}}""");

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details!.Isbn.Should().Be("0399142032");
    }

    [Fact]
    public async Task SearchBooksAsync_SearchesByIsbnAlone_WhenIsbnIsSupplied()
    {
        string? capturedQuery = null;
        var client = BuildClient(request =>
        {
            capturedQuery = request.RequestUri!.Query;
            return """{"items":[{"id":"id1","volumeInfo":{"title":"Killing Floor","authors":["Lee Child"],"publishedDate":"1997"}}]}""";
        });

        var results = await client.SearchBooksAsync("Some Title That Should Be Ignored", null, "Some Author That Should Be Ignored", "9780399142034",
            TestContext.Current.CancellationToken);

        results.Should().ContainSingle();
        capturedQuery.Should().Contain("isbn").And.NotContain("intitle").And.NotContain("inauthor");
    }

    [Fact]
    public async Task GetBookDetailsAsync_ReturnsNull_WhenTheVolumeHasNoTitle()
    {
        var client = BuildClient(_ => """{"id":"abc123","volumeInfo":{}}""");

        var details = await client.GetBookDetailsAsync("abc123", TestContext.Current.CancellationToken);

        details.Should().BeNull();
    }

    [Fact]
    public async Task SearchBooksAsync_ParsesMultipleResults()
    {
        var client = BuildClient(_ => """
            {
              "items": [
                { "id": "id1", "volumeInfo": { "title": "Killing Floor", "authors": ["Lee Child"], "publishedDate": "1997" } },
                { "id": "id2", "volumeInfo": { "title": "Die Trying", "authors": ["Lee Child"], "publishedDate": "1998" } }
              ]
            }
            """);

        var results = await client.SearchBooksAsync("Some Query", null, cancellationToken: TestContext.Current.CancellationToken);

        results.Should().HaveCount(2);
        results[0].ExternalId.Should().Be("id1");
        results[1].Year.Should().Be(1998);
    }

    [Fact]
    public async Task SearchBooksAsync_RetriesWithoutTheAuthor_WhenTheNarrowedSearchReturnsNoResults()
    {
        var authorSearchAttempted = false;
        var client = BuildClient(request =>
        {
            if (request.RequestUri!.Query.Contains("inauthor"))
            {
                authorSearchAttempted = true;
                return """{"items":[]}""";
            }

            return """{"items":[{"id":"id1","volumeInfo":{"title":"Killing Floor","authors":["Lee Child"],"publishedDate":"1997"}}]}""";
        });

        var results = await client.SearchBooksAsync("Killing Floor", 1997, "Some Mismatched Author Text", cancellationToken: TestContext.Current.CancellationToken);

        authorSearchAttempted.Should().BeTrue();
        results.Should().ContainSingle();
    }
}
