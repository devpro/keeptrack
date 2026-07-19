using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// BnF (Bibliothèque nationale de France) "Catalogue général" SRU client - free, keyless, public.
/// Unlike every other provider here (JSON), SRU responses are XML: each hit is a <c>srw:record</c> whose
/// <c>srw:recordData</c> embeds a Dublin Core (<c>oai_dc:dc</c>) document. Confirmed against the real API
/// (searching "Killing Floor" / Lee Child, then re-fetching by <c>bib.persistentid</c>) before writing this
/// parser - the exact element/namespace shape below is not guessed from documentation prose.
/// Deliberately never populates <see cref="BookSearchResult.ImageUrl"/>/<see cref="BookDetails.ImageUrl"/>:
/// BnF's ordinary catalogue records carry no cover-art field at all (only a digitized Gallica item would,
/// via a separate API this client doesn't call), unlike Open Library/RAWG/Discogs.
/// </summary>
public class BnfClient(HttpClient http) : IBookReferenceClient
{
    public string ProviderKey => "bnf";

    public string DisplayName => "BnF";

    private static readonly XNamespace s_srw = "http://www.loc.gov/zing/srw/";
    private static readonly XNamespace s_dc = "http://purl.org/dc/elements/1.1/";

    private const int MaxGenres = 5;

    /// <summary>
    /// <paramref name="year"/> is deliberately never sent to BnF as a query criterion, same choice
    /// <see cref="OpenLibraryClient"/> makes (see its own doc comment) though for a different reason here:
    /// BnF's own "and" combination was confirmed unreliable for narrowing (see <see cref="SearchBooksCoreAsync"/>),
    /// so stacking a second server-side "and" clause on top of the author one would only compound that risk.
    /// <c>dc:date</c> is still parsed and returned per candidate (<see cref="BookSearchResult.Year"/>) for
    /// the admin to use when picking, exactly like every other provider here.
    /// </summary>
    /// <summary>
    /// <paramref name="isbn"/> is accepted (interface compliance) but ignored as a search input - only
    /// <see cref="GoogleBooksClient"/> currently searches by it. BnF's own catalogue records do sometimes
    /// carry an ISBN (via <c>dc:identifier</c>, confirmed against the real API), which is still parsed and
    /// returned by <see cref="GetBookDetailsAsync"/> for autofill on link/refresh - searching by it and
    /// merely reporting one already-known are different things.
    /// </summary>
    public async Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchBooksCoreAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // Same "an optional narrowing parameter must never silently zero out results" lesson as
            // OpenLibraryClient/DiscogsClient - a tenant's plain author text can fail to match BnF's own
            // "LastName, FirstName (dates). Role" creator indexing even when the title alone would find it.
            results = await SearchBooksCoreAsync(title, null, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// <paramref name="author"/>, when given, is both sent to BnF as an "and (bib.author ...)" clause AND
    /// re-checked client-side afterward - confirmed against the real API that BnF's own "and" combination
    /// is not a strict intersection for every author: querying title "La Peste" and author "Victor Hugo"
    /// (who never wrote a book by that title) returns several real Hugo anthologies instead of zero, none
    /// of them actually titled "La Peste". The server-side clause still narrows the common, well-populated
    /// case (confirmed correct for "Killing Floor"/Lee Child and "La Peste"/Albert Camus, both genuine
    /// matches), but a candidate that slips through without a real author match must be filtered out here
    /// rather than trusted - otherwise search results silently include titles that don't match the
    /// requested author at all, which read as "the author was ignored".
    /// </summary>
    private async Task<IReadOnlyList<BookSearchResult>> SearchBooksCoreAsync(string title, string? author, CancellationToken cancellationToken)
    {
        var xml = await FetchAsync(BuildCqlQuery(title, author), cancellationToken);
        var records = ParseRecords(xml);
        if (!string.IsNullOrEmpty(author))
        {
            records = records.Where(r => AuthorMatches(r.Author, author));
        }

        return records.Select(r => new BookSearchResult(r.ExternalId, r.Title, r.Year, r.Author, null)).ToList();
    }

    /// <summary>
    /// True when every word of <paramref name="requestedAuthor"/> appears somewhere in
    /// <paramref name="candidateAuthor"/> - a plain substring/word-presence check (same normalization,
    /// <see cref="TitleNormalizer.Normalize"/>, already used for title matching elsewhere), not an exact
    /// match: <paramref name="candidateAuthor"/> already went through <see cref="ExtractAuthorName"/>'s
    /// reordering, but a multi-author record's <c>dc:creator</c> only ever contributes the FIRST credited
    /// name to this parser, so this stays a loose contains-check rather than requiring exact equality.
    /// </summary>
    private static bool AuthorMatches(string? candidateAuthor, string requestedAuthor)
    {
        if (string.IsNullOrEmpty(candidateAuthor)) return false;

        var normalizedCandidate = TitleNormalizer.Normalize(candidateAuthor);
        return requestedAuthor
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .All(word => normalizedCandidate.Contains(TitleNormalizer.Normalize(word)));
    }

    public async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        // externalId is the bare ARK (e.g. "ark:/12148/cb361713613") from srw:recordIdentifier - re-querying
        // by bib.persistentid is the one exact-id search criterion confirmed to round-trip it back to the
        // same single record.
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
    /// <c>srw:recordData</c>'s only child is the <c>oai_dc:dc</c> wrapper - read it positionally rather than
    /// by name, so this doesn't depend on assuming the oai_dc namespace prefix/URI stays exactly as observed.
    /// A record missing an id or a title (shouldn't happen for a real bibliographic hit) is skipped rather
    /// than surfaced as a broken candidate.
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
    /// <c>dc:identifier</c> is repeatable and mixes different identifier kinds in the same element (an ARK
    /// URL, an ISBN as plain text "ISBN 2841142787" - confirmed against the real API) - the ARK is already
    /// captured separately via <c>srw:recordIdentifier</c>, so this only looks for the ISBN-prefixed one.
    /// </summary>
    private static readonly Regex s_isbnRegex = new(@"^ISBN\s+(.+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static string? ExtractIsbn(IEnumerable<XElement> identifiers) =>
        identifiers
            .Select(e => s_isbnRegex.Match(e.Value))
            .FirstOrDefault(m => m.Success)
            ?.Groups[1].Value.Trim();

    /// <summary>
    /// BnF's <c>dc:creator</c> is formatted "LastName, FirstName (birth-death dates). Role" (e.g. "Child,
    /// Lee (1954-....). Auteur du texte", confirmed against the real API) - strips the trailing role
    /// sentence and the parenthetical dates, then reorders "LastName, FirstName" to "FirstName LastName" to
    /// match the plain-name shape every other provider here returns. Left as-is (just parenthetical-
    /// stripped) when there's no comma to reorder around (e.g. a corporate/collective author).
    /// </summary>
    private static string? ExtractAuthorName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var namePart = raw.Split(". ", 2)[0];
        namePart = Regex.Replace(namePart, @"\s*\([^)]*\)", "").Trim();

        var parts = namePart.Split(", ", 2);
        return parts.Length == 2 ? $"{parts[1]} {parts[0]}".Trim() : namePart;
    }

    /// <summary>
    /// <c>dc:date</c> is usually a bare 4-digit year (confirmed "1997" for a real record) but library
    /// catalogue dates can carry uncertainty markers or ranges - a defensive last-4-digit-token extraction,
    /// same shape as <see cref="OpenLibraryClient"/>'s own year parsing, rather than a bare <c>int.Parse</c>.
    /// </summary>
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled);

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var matches = s_yearRegex.Matches(date);
        return matches.Count > 0 && int.TryParse(matches[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }
}
