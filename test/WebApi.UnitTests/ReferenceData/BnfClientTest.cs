using System;
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
/// <see cref="BnfClient"/> parses SRU/XML (Dublin Core), unlike every other provider here (JSON) - the
/// sample response shapes below are trimmed but otherwise verbatim from the real API (searched "Killing
/// Floor" / Lee Child, then re-fetched by <c>bib.persistentid</c>), not guessed from documentation prose.
/// </summary>
[Trait("Category", "UnitTests")]
public class BnfClientTest
{
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(respond(request), Encoding.UTF8, "application/xml")
            });
    }

    private static BnfClient BuildClient(Func<HttpRequestMessage, string> respond)
    {
        var http = new HttpClient(new StubHttpMessageHandler(respond)) { BaseAddress = new Uri("https://catalogue.bnf.fr/api/") };
        return new BnfClient(http);
    }

    private static string OneRecordResponse(string externalId, string title, string creator, string date, string language) =>
        RecordsResponse((externalId, title, creator, date, language));

    private static string RecordsResponse(params (string ExternalId, string Title, string Creator, string Date, string Language)[] records)
    {
        var recordsXml = string.Join("\n", records.Select(r => $"""
            <srw:record>
              <srw:recordData>
                <oai_dc:dc xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/" xmlns:dc="http://purl.org/dc/elements/1.1/">
                  <dc:identifier>http://catalogue.bnf.fr/{r.ExternalId}</dc:identifier>
                  <dc:title>{r.Title}</dc:title>
                  <dc:creator>{r.Creator}</dc:creator>
                  <dc:date>{r.Date}</dc:date>
                  <dc:language>{r.Language}</dc:language>
                </oai_dc:dc>
              </srw:recordData>
              <srw:recordIdentifier>{r.ExternalId}</srw:recordIdentifier>
            </srw:record>
            """));

        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <srw:searchRetrieveResponse xmlns:srw="http://www.loc.gov/zing/srw/">
              <srw:numberOfRecords>{records.Length}</srw:numberOfRecords>
              <srw:records>
            {recordsXml}
              </srw:records>
            </srw:searchRetrieveResponse>
            """;
    }

    [Fact]
    public void ProviderKey_IsBnf() => BuildClient(_ => "").ProviderKey.Should().Be("bnf");

    [Fact]
    public void DisplayName_IsBnf() => BuildClient(_ => "").DisplayName.Should().Be("BnF");

    [Fact]
    public async Task GetBookDetailsAsync_ParsesTitleYearLanguageAndCleansUpTheCreatorName()
    {
        var client = BuildClient(_ => OneRecordResponse("ark:/12148/cb361713613", "Du fond de l'abîme", "Child, Lee (1954-....). Auteur du texte", "1997", "fre"));

        var details = await client.GetBookDetailsAsync("ark:/12148/cb361713613", TestContext.Current.CancellationToken);

        details!.Title.Should().Be("Du fond de l'abîme");
        details.Year.Should().Be(1997);
        details.Language.Should().Be("fre");
        // "LastName, FirstName (dates). Role" -> "FirstName LastName" - confirmed against the real API's
        // own creator formatting for this exact record.
        details.Author.Should().Be("Lee Child");
        details.ImageUrl.Should().BeNull();
    }

    [Fact]
    public async Task GetBookDetailsAsync_LeavesACreatorWithNoCommaUnchanged()
    {
        // a corporate/collective author has no "LastName, FirstName" shape to reorder around
        var client = BuildClient(_ => OneRecordResponse("ark:/12148/cb2", "Some Title", "Bibliothèque nationale de France", "2001", "fre"));

        var details = await client.GetBookDetailsAsync("ark:/12148/cb2", TestContext.Current.CancellationToken);

        details!.Author.Should().Be("Bibliothèque nationale de France");
    }

    [Fact]
    public async Task GetBookDetailsAsync_ParsesTheIsbnFromTheIsbnPrefixedIdentifier()
    {
        // dc:identifier is repeatable and mixes kinds (the ARK URL and, when present, a plain "ISBN ..."
        // string) - confirmed verbatim against the real API for this exact record.
        var client = BuildClient(_ => """
            <?xml version="1.0" encoding="UTF-8"?>
            <srw:searchRetrieveResponse xmlns:srw="http://www.loc.gov/zing/srw/">
              <srw:numberOfRecords>1</srw:numberOfRecords>
              <srw:records>
                <srw:record>
                  <srw:recordData>
                    <oai_dc:dc xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/" xmlns:dc="http://purl.org/dc/elements/1.1/">
                      <dc:identifier>http://catalogue.bnf.fr/ark:/12148/cb361713613</dc:identifier>
                      <dc:title>Du fond de l'abîme</dc:title>
                      <dc:creator>Child, Lee (1954-....). Auteur du texte</dc:creator>
                      <dc:date>1997</dc:date>
                      <dc:identifier>ISBN 2841142787</dc:identifier>
                      <dc:language>fre</dc:language>
                    </oai_dc:dc>
                  </srw:recordData>
                  <srw:recordIdentifier>ark:/12148/cb361713613</srw:recordIdentifier>
                </srw:record>
              </srw:records>
            </srw:searchRetrieveResponse>
            """);

        var details = await client.GetBookDetailsAsync("ark:/12148/cb361713613", TestContext.Current.CancellationToken);

        details!.Isbn.Should().Be("2841142787");
    }

    [Fact]
    public async Task GetBookDetailsAsync_LeavesIsbnNull_WhenNoIdentifierIsIsbnPrefixed()
    {
        var client = BuildClient(_ => OneRecordResponse("ark:/12148/cb361713613", "Du fond de l'abîme", "Child, Lee (1954-....). Auteur du texte", "1997", "fre"));

        var details = await client.GetBookDetailsAsync("ark:/12148/cb361713613", TestContext.Current.CancellationToken);

        details!.Isbn.Should().BeNull();
    }

    [Fact]
    public async Task SearchBooksAsync_ParsesResultsWithNoImageUrl()
    {
        // BnF's ordinary catalogue records carry no cover-art field at all - confirmed against the real API.
        var client = BuildClient(_ => OneRecordResponse("ark:/12148/cb361713613", "Du fond de l'abîme", "Child, Lee (1954-....). Auteur du texte", "1997", "fre"));

        var results = await client.SearchBooksAsync("Du fond de l'abime", 1997, cancellationToken: TestContext.Current.CancellationToken);

        results.Should().ContainSingle();
        results[0].ExternalId.Should().Be("ark:/12148/cb361713613");
        results[0].Author.Should().Be("Lee Child");
        results[0].ImageUrl.Should().BeNull();
    }

    [Fact]
    public async Task SearchBooksAsync_RetriesWithoutTheAuthor_WhenTheNarrowedSearchReturnsNoResults()
    {
        var authorSearchAttempted = false;
        var client = BuildClient(request =>
        {
            if (request.RequestUri!.Query.Contains("bib.author"))
            {
                authorSearchAttempted = true;
                return """<srw:searchRetrieveResponse xmlns:srw="http://www.loc.gov/zing/srw/"><srw:numberOfRecords>0</srw:numberOfRecords><srw:records/></srw:searchRetrieveResponse>""";
            }

            return OneRecordResponse("ark:/12148/cb361713613", "Du fond de l'abîme", "Child, Lee (1954-....). Auteur du texte", "1997", "fre");
        });

        var results = await client.SearchBooksAsync("Du fond de l'abime", 1997, "Some Mismatched Author Text", cancellationToken: TestContext.Current.CancellationToken);

        authorSearchAttempted.Should().BeTrue();
        results.Should().ContainSingle();
    }

    [Fact]
    public async Task SearchBooksAsync_FiltersOutCandidatesWhoseAuthorDoesNotActuallyMatch()
    {
        // regression: confirmed against the real API that BnF's own "and (bib.author ...)" combination is
        // not a strict intersection - a query for title "La Peste" and author "Victor Hugo" (who never wrote
        // a book by that title) returned several genuine Victor Hugo anthologies instead of zero, none of
        // them actually titled "La Peste". The client must not trust the server's own filtering here.
        var client = BuildClient(_ => RecordsResponse(
            ("ark:/12148/cb1", "La peste", "Camus, Albert (1913-1960). Auteur du texte", "1947", "fre"),
            ("ark:/12148/cb2", "Chemins de la poésie", "Hugo, Victor (1802-1885). Auteur du texte", "1956", "fre")));

        var results = await client.SearchBooksAsync("La Peste", null, "Albert Camus", cancellationToken: TestContext.Current.CancellationToken);

        results.Should().ContainSingle();
        results[0].ExternalId.Should().Be("ark:/12148/cb1");
        results[0].Author.Should().Be("Albert Camus");
    }
}
