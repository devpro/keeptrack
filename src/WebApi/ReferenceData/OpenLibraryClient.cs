using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Open Library REST client.
/// No API key required;
/// registered as a typed <see cref="HttpClient"/> with a descriptive User-Agent header (Open Library's stated best practice for API consumers) - see Program.cs.
/// </summary>
public class OpenLibraryClient(HttpClient http) : IBookReferenceClient
{
    public string ProviderKey => "openlibrary";

    public string DisplayName => "Open Library";

    /// <summary>
    /// Deliberately does NOT filter server-side by <paramref name="year"/>:
    /// Open Library's <c>first_publish_year</c> is the work's ORIGINAL publication year,
    /// which routinely differs from whatever edition/printing year a tenant recorded (e.g. a 1997 first edition vs. a 2016 reprint) -
    /// filtering on it would silently drop the real match instead of just ranking it lower.
    /// This is an Open-Library-specific workaround, not a rule every <see cref="IBookReferenceClient"/> must follow.
    /// <paramref name="isbn"/> is accepted (interface compliance) but ignored - only <see cref="GoogleBooksClient"/>
    /// currently uses it as a search input.
    /// </summary>
    public async Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchBooksCoreAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // same "an optional narrowing parameter must not silently produce zero results" lesson as the year filter above:
            // an author string that doesn't exactly match Open Library's own indexing (a middle name, a diacritic, "and" vs "&") can zero out results the title alone would find -
            // see DiscogsClient.SearchAlbumsAsync for the equivalent fallback with the same rationale.
            results = await SearchBooksCoreAsync(title, null, cancellationToken);
        }

        return results;
    }

    private async Task<IReadOnlyList<BookSearchResult>> SearchBooksCoreAsync(string title, string? author, CancellationToken cancellationToken)
    {
        // General relevance query (q=), not the title= field-scoped match: title= only matches a work's own
        // canonical title text, which misses regional title variants entirely - confirmed against the real
        // API for "Harry Potter and the Sorcerer's Stone" (the US title): title= only finds a handful of
        // near-empty 1-edition work stubs, because Open Library's canonical work for this book is titled
        // "Harry Potter and the Philosopher's Stone" (the UK title) with 398 editions - q= surfaces that
        // well-populated canonical work first instead, since it ranks by relevance across alternate titles
        // too, not just an exact field match. year is intentionally never sent as a query filter here - see
        // this class's own SearchBooksAsync doc comment above.
        var query = $"search.json?q={Encode(title)}" + (string.IsNullOrEmpty(author) ? "" : $"&author={Encode(author)}");
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>(query, cancellationToken);
        return response?.Docs
            .Where(d => !string.IsNullOrEmpty(d.Key))
            .Select(d => new BookSearchResult(d.Key!, d.Title ?? title, d.FirstPublishYear, d.AuthorName.FirstOrDefault(), BuildCoverUrl(d.CoverId)))
            .ToList() ?? [];
    }

    public async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var work = await http.GetFromJsonAsync<OpenLibraryWorkResponse>($"{externalId}.json", cancellationToken);
        if (work is null) return null;

        var authorKey = work.Authors.Select(a => a.Author?.Key).FirstOrDefault(k => !string.IsNullOrEmpty(k));
        string? authorName = null;
        string? authorExternalId = null;
        if (!string.IsNullOrEmpty(authorKey))
        {
            authorExternalId = authorKey.Split('/').Last();
            var author = await http.GetFromJsonAsync<OpenLibraryAuthorResponse>($"{authorKey}.json", cancellationToken);
            authorName = author?.Name;
        }

        var year = ParseYear(work.FirstPublishDate) ?? await FindPublishYearViaSearchAsync(externalId, cancellationToken);

        return new BookDetails(
            externalId,
            work.Title ?? string.Empty,
            year,
            ExtractDescription(work.Description),
            authorName,
            authorExternalId,
            work.Subjects.Take(MaxGenres).ToList(),
            BuildCoverUrl(work.Covers.FirstOrDefault()));
    }

    /// <summary>
    /// Falls back to the search index's <c>first_publish_year</c> when the work's own JSON has no
    /// <c>first_publish_date</c> at all - confirmed against the real API this is common even for
    /// well-known books (e.g. Lee Child's "Killing Floor", OL24477958W, has no <c>first_publish_date</c>
    /// on its work document), while the search index's computed <c>first_publish_year</c> is reliable.
    /// A single-document, id-scoped query (<c>q=key:{workKey}</c>), not a general title search - the exact
    /// same work document, just re-fetched from the index instead of the object endpoint.
    /// </summary>
    private async Task<int?> FindPublishYearViaSearchAsync(string workKey, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>($"search.json?q={Encode($"key:{workKey}")}", cancellationToken);
        return response?.Docs.FirstOrDefault()?.FirstPublishYear;
    }

    /// <summary>
    /// Open Library's work <c>description</c> field is documented as either a plain JSON string or an
    /// object shaped <c>{ "type": "/type/text", "value": "..." }</c> - both shapes are handled here so the
    /// wire model can stay a plain <see cref="JsonElement"/> instead of a custom converter.
    /// </summary>
    private static string? ExtractDescription(JsonElement? description) => description?.ValueKind switch
    {
        JsonValueKind.String => description.Value.GetString(),
        JsonValueKind.Object when description.Value.TryGetProperty("value", out var value) => value.GetString(),
        _ => null
    };

    private const int MaxGenres = 5;

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    /// <summary>
    /// Matches a standalone 4-digit token (word-boundary delimited, so it can't match the first 4 digits of
    /// a longer run) - <c>first_publish_date</c> is often "Month Day, Year" (e.g. "November 12, 1972"), and
    /// naively stripping all digits and taking the first 4 previously mis-parsed that as 1219 (day "12" then
    /// the leading digits of "1972") instead of 1972 - confirmed against the real API for Tolkien's "The
    /// Fellowship of the Ring" (OL27513W). The year is the last such token, since it's always what trails
    /// the day/month when both are present, and the only token when the date is a bare year.
    /// </summary>
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled);

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var matches = s_yearRegex.Matches(date);
        return matches.Count > 0 && int.TryParse(matches[^1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }

    /// <summary>
    /// Open Library's cover CDN is a separate, unauthenticated static-asset host explicitly meant for
    /// direct hotlinking - same pattern as TMDB's image CDN, just this provider's own host/id shape.
    /// </summary>
    private static string? BuildCoverUrl(int? coverId) =>
        coverId is null or 0 ? null : $"https://covers.openlibrary.org/b/id/{coverId}-L.jpg";

    private sealed class OpenLibrarySearchResponse
    {
        [JsonPropertyName("docs")]
        public List<OpenLibrarySearchDoc> Docs { get; set; } = [];
    }

    private sealed class OpenLibrarySearchDoc
    {
        [JsonPropertyName("key")]
        public string? Key { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("first_publish_year")]
        public int? FirstPublishYear { get; set; }

        [JsonPropertyName("author_name")]
        public List<string> AuthorName { get; set; } = [];

        [JsonPropertyName("cover_i")]
        public int? CoverId { get; set; }
    }

    private sealed class OpenLibraryWorkResponse
    {
        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("description")]
        public JsonElement? Description { get; set; }

        [JsonPropertyName("first_publish_date")]
        public string? FirstPublishDate { get; set; }

        [JsonPropertyName("subjects")]
        public List<string> Subjects { get; set; } = [];

        [JsonPropertyName("covers")]
        public List<int> Covers { get; set; } = [];

        [JsonPropertyName("authors")]
        public List<OpenLibraryWorkAuthor> Authors { get; set; } = [];
    }

    private sealed class OpenLibraryWorkAuthor
    {
        [JsonPropertyName("author")]
        public OpenLibraryAuthorKey? Author { get; set; }
    }

    private sealed class OpenLibraryAuthorKey
    {
        [JsonPropertyName("key")]
        public string? Key { get; set; }
    }

    private sealed class OpenLibraryAuthorResponse
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}
