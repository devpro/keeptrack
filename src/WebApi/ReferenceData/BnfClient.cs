using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// SRU client of the BnF (Bibliothèque nationale de France) "Catalogue général", free and keyless.
/// Unlike the other providers, it answers XML: each hit is a <c>srw:record</c> whose <c>srw:recordData</c> embeds a Dublin Core (<c>oai_dc:dc</c>) document.
/// The element and namespace shape below comes from real responses, not documentation prose.
/// It never fills <see cref="BookSearchResult.ImageUrl"/> or <see cref="BookDetails.ImageUrl"/>,
/// since catalogue records carry no cover (only a digitized Gallica item would, through another API).
/// </summary>
public class BnfClient(HttpClient http) : BookReferenceClientBase
{
    public override string ProviderKey => "bnf";

    public override string DisplayName => "BnF";

    private static readonly XNamespace s_srw = "http://www.loc.gov/zing/srw/";
    private static readonly XNamespace s_dc = "http://purl.org/dc/elements/1.1/";

    private const int MaxGenres = 5;

    private static readonly TimeSpan s_regexTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// <c>bib.isbn</c> is exact, so unlike the author clause it needs no check: <c>2841142787</c> returns the one record, Lee Child's "Du fond de l'abîme".
    /// BnF's catalogue is much narrower than Google Books', so a miss is routine and widens to the title search (see <see cref="BookReferenceClientBase.SearchBooksAsync"/>).
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken) =>
        SearchCoreAsync($"bib.isbn all \"{EscapeCql(isbn)}\"", null, cancellationToken);

    /// <summary>
    /// <paramref name="author"/> is sent as an "and (bib.author ...)" clause and checked again here, since BnF's "and" is not a strict intersection.
    /// "La Peste" by "Victor Hugo", who never wrote it, returns several Hugo anthologies rather than nothing.
    /// The clause still narrows the ordinary case, but a candidate without a real author match is filtered out, or results would seem to ignore the author.
    /// <para>
    /// No year clause, since stacking a second unreliable "and" only adds risk.
    /// <c>dc:date</c> is still returned per candidate (<see cref="BookSearchResult.Year"/>) for the admin to pick with.
    /// </para>
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken) =>
        SearchCoreAsync(BuildCqlQuery(title, author), author, cancellationToken);

    /// <summary>
    /// <paramref name="authorToVerify"/> checks the parsed creator, null skipping it for a query whose criterion is already exact.
    /// </summary>
    private async Task<IReadOnlyList<BookSearchResult>> SearchCoreAsync(string cqlQuery, string? authorToVerify, CancellationToken cancellationToken)
    {
        var xml = await FetchAsync(cqlQuery, cancellationToken);
        var records = ParseRecords(xml);
        if (!string.IsNullOrEmpty(authorToVerify))
        {
            records = records.Where(r => AuthorMatches(r.Author, authorToVerify));
        }

        return records.Select(r => new BookSearchResult(r.ExternalId, r.Title, r.Year, r.Author, null)).ToList();
    }

    /// <summary>
    /// True when every word of <paramref name="requestedAuthor"/> appears in <paramref name="candidateAuthor"/>, under <see cref="TitleNormalizer.Normalize"/>.
    /// A loose containment rather than equality, since a multi-author record's <c>dc:creator</c> gives this parser only the first credited name.
    /// </summary>
    private static bool AuthorMatches(string? candidateAuthor, string requestedAuthor)
    {
        if (string.IsNullOrEmpty(candidateAuthor)) return false;

        var normalizedCandidate = TitleNormalizer.Normalize(candidateAuthor);
        return requestedAuthor
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .All(word => normalizedCandidate.Contains(TitleNormalizer.Normalize(word)));
    }

    public override async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        // externalId is the bare ARK ("ark:/12148/cb361713613") of srw:recordIdentifier, and bib.persistentid is the criterion returning that one record
        var xml = await FetchAsync($"bib.persistentid all \"{externalId}\"", cancellationToken);
        var record = ParseRecords(xml).FirstOrDefault();
        return record is null ? null : new BookDetails(record.ExternalId, record.Title, record.Year, record.Synopsis, record.Author, null, record.Genres, null, record.Language, record.Isbn);
    }

    private async Task<string> FetchAsync(string cqlQuery, CancellationToken cancellationToken)
    {
        var query = $"SRU?version=1.2&operation=searchRetrieve&recordSchema=dublincore&maximumRecords=20&query={Uri.EscapeDataString(cqlQuery)}";
        return await http.GetStringAsync(query, cancellationToken);
    }

    private static string BuildCqlQuery(string title, string? author)
    {
        var clause = $"bib.title all \"{EscapeCql(title)}\"";
        return string.IsNullOrEmpty(author) ? clause : $"{clause} and (bib.author all \"{EscapeCql(author)}\")";
    }

    private static string EscapeCql(string value) => value.Replace("\"", "\\\"");

    private sealed record ParsedRecord(string ExternalId, string Title, int? Year, string? Author, string? Synopsis, string? Language, List<string> Genres, string? Isbn);

    /// <summary>
    /// <c>srw:recordData</c>'s only child is the <c>oai_dc:dc</c> wrapper, read by position rather than name, so a change of namespace prefix does not matter.
    /// A record without an id or title is skipped rather than shown as a broken candidate.
    /// </summary>
    private static IEnumerable<ParsedRecord> ParseRecords(string xml)
    {
        var doc = XDocument.Parse(xml);
        foreach (var record in doc.Descendants(s_srw + "record"))
        {
            var externalId = record.Element(s_srw + "recordIdentifier")?.Value;
            var dc = record.Element(s_srw + "recordData")?.Elements().FirstOrDefault();
            var title = dc?.Element(s_dc + "title")?.Value;
            if (string.IsNullOrEmpty(externalId) || string.IsNullOrEmpty(title)) continue;

            yield return new ParsedRecord(
                externalId,
                title,
                ParseYear(dc!.Element(s_dc + "date")?.Value),
                ExtractAuthorName(dc.Element(s_dc + "creator")?.Value),
                dc.Element(s_dc + "description")?.Value,
                dc.Element(s_dc + "language")?.Value,
                dc.Elements(s_dc + "subject").Select(e => e.Value).Where(v => !string.IsNullOrEmpty(v)).Take(MaxGenres).ToList(),
                ExtractIsbn(dc.Elements(s_dc + "identifier")));
        }
    }

    /// <summary>
    /// <c>dc:identifier</c> repeats and mixes kinds (an ARK URL, "ISBN 2841142787"), and the ARK comes from <c>srw:recordIdentifier</c>, so this only reads the ISBN one.
    /// </summary>
    private static readonly Regex s_isbnRegex = new(@"^ISBN\s+(.+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled, s_regexTimeout);

    private static string? ExtractIsbn(IEnumerable<XElement> identifiers) =>
        identifiers
            .Select(e => s_isbnRegex.Match(e.Value))
            .FirstOrDefault(m => m.Success)
            ?.Groups[1].Value.Trim();

    /// <summary>
    /// BnF's <c>dc:creator</c> reads "LastName, FirstName (dates). Role" ("Child, Lee (1954-....). Auteur du texte").
    /// The role and dates are stripped and the name reordered to "FirstName LastName", like the other providers.
    /// Without a comma, a corporate author, only the dates are stripped.
    /// </summary>
    private static string? ExtractAuthorName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var namePart = raw.Split(". ", 2)[0];
        namePart = Regex.Replace(namePart, @"\s*\([^)]*\)", "", RegexOptions.None, s_regexTimeout).Trim();

        var parts = namePart.Split(", ", 2);
        return parts.Length == 2 ? $"{parts[1]} {parts[0]}".Trim() : namePart;
    }

    /// <summary>
    /// <c>dc:date</c> is usually a bare year, but catalogue dates can carry uncertainty markers or ranges,
    /// so the last 4-digit token is read, as in <see cref="OpenLibraryClient"/>.
    /// </summary>
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled, s_regexTimeout);

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var matches = s_yearRegex.Matches(date);
        return matches.Count > 0 && int.TryParse(matches[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }
}
