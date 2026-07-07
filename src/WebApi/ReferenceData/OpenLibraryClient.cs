using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Open Library REST client. No API key required; registered as a typed <see cref="HttpClient"/> with a
/// descriptive User-Agent header (Open Library's stated best practice for API consumers) - see Program.cs.
/// </summary>
public class OpenLibraryClient(HttpClient http) : IOpenLibraryClient
{
    public async Task<IReadOnlyList<OpenLibrarySearchResult>> SearchBooksAsync(string title, int? year, string? author = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchBooksCoreAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // same "an optional narrowing parameter must not silently produce zero results" lesson as the
            // year filter above: an author string that doesn't exactly match Open Library's own indexing
            // (a middle name, a diacritic, "and" vs "&") can zero out results the title alone would find -
            // see DiscogsClient.SearchAlbumsAsync for the equivalent fallback with the same rationale.
            results = await SearchBooksCoreAsync(title, null, cancellationToken);
        }

        return results;
    }

    private async Task<IReadOnlyList<OpenLibrarySearchResult>> SearchBooksCoreAsync(string title, string? author, CancellationToken cancellationToken)
    {
        // General relevance query (q=), not the title= field-scoped match: title= only matches a work's own
        // canonical title text, which misses regional title variants entirely - confirmed against the real
        // API for "Harry Potter and the Sorcerer's Stone" (the US title): title= only finds a handful of
        // near-empty 1-edition work stubs, because Open Library's canonical work for this book is titled
        // "Harry Potter and the Philosopher's Stone" (the UK title) with 398 editions - q= surfaces that
        // well-populated canonical work first instead, since it ranks by relevance across alternate titles
        // too, not just an exact field match. year is intentionally never sent as a query filter here - see
        // IOpenLibraryClient.SearchBooksAsync's doc comment.
        var query = $"search.json?q={Encode(title)}" + (string.IsNullOrEmpty(author) ? "" : $"&author={Encode(author)}");
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>(query, cancellationToken);
        return response?.Docs
            .Where(d => !string.IsNullOrEmpty(d.Key))
            .Select(d => new OpenLibrarySearchResult(d.Key!, d.Title ?? title, d.FirstPublishYear, d.AuthorName.FirstOrDefault(), BuildCoverUrl(d.CoverId)))
            .ToList() ?? [];
    }

    public async Task<OpenLibraryBookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
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

        return new OpenLibraryBookDetails(
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

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var digits = new string(date.Where(char.IsDigit).ToArray());
        return digits.Length >= 4 && int.TryParse(digits[..4], NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
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
