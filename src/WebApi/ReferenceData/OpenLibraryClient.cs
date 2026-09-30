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
public class OpenLibraryClient(HttpClient http) : BookReferenceClientBase, IBookRatingByIsbnLookup
{
    public override string ProviderKey => "openlibrary";

    public override string DisplayName => "Open Library";

    private static readonly TimeSpan s_regexTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The search index answers an <c>isbn:</c> query directly, returning the work the edition belongs to -
    /// the same index and the same one-call shape <see cref="GetRatingByIsbnAsync"/> already relies on,
    /// just projecting the display fields instead of the rating ones. Confirmed against the real API:
    /// <c>q=isbn:9782265002104</c> returns exactly one work (title, year, authors and a cover id), the same
    /// French edition Google Books was the only provider able to find until this existed.
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken) =>
        RunSearchAsync($"search.json?q={Encode($"isbn:{isbn}")}", null, cancellationToken);

    /// <summary>
    /// General relevance query (<c>q=</c>), not the <c>title=</c> field-scoped match: <c>title=</c> only
    /// matches a work's own canonical title text, which misses regional title variants entirely - confirmed
    /// against the real API for "Harry Potter and the Sorcerer's Stone" (the US title): <c>title=</c> only
    /// finds a handful of near-empty 1-edition work stubs, because Open Library's canonical work for this book
    /// is titled "Harry Potter and the Philosopher's Stone" (the UK title) with 398 editions - <c>q=</c>
    /// surfaces that well-populated canonical work first instead, since it ranks by relevance across alternate
    /// titles too, not just an exact field match.
    /// <para>
    /// No year is sent as a query filter, and that is this provider's own reason rather than the shared one:
    /// Open Library's <c>first_publish_year</c> is the work's ORIGINAL publication year, which routinely
    /// differs from whatever edition/printing year a tenant recorded (e.g. a 1997 first edition vs. a 2016
    /// reprint), so filtering on it would silently drop the real match instead of just ranking it lower.
    /// </para>
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken) =>
        RunSearchAsync(
            $"search.json?q={Encode(title)}" + (string.IsNullOrEmpty(author) ? "" : $"&author={Encode(author)}"),
            title,
            cancellationToken);

    /// <summary>
    /// <paramref name="titleFallback"/> is the text that was searched for, used when a matched doc carries no
    /// title of its own - available only on the title path, so an identifier search that turns up a titleless
    /// stub drops it rather than labelling it with an ISBN.
    /// </summary>
    private async Task<IReadOnlyList<BookSearchResult>> RunSearchAsync(string query, string? titleFallback, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>(query, cancellationToken);
        return response?.Docs
            .Where(d => !string.IsNullOrEmpty(d.Key))
            .Select(d => new BookSearchResult(d.Key!, d.Title ?? titleFallback ?? string.Empty, d.FirstPublishYear, d.AuthorName.FirstOrDefault(),
                BuildCoverUrl(d.CoverId)))
            .Where(r => !string.IsNullOrEmpty(r.Title))
            .ToList() ?? [];
    }

    public override async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var work = await http.GetFromJsonAsync<OpenLibraryWorkResponse>($"{externalId}.json", cancellationToken);
        if (work is null) return null;

        var authorKey = work.Authors.Select(a => a.Author?.Key).FirstOrDefault(k => !string.IsNullOrEmpty(k));
        string? authorName = null;
        string? authorExternalId = null;
        if (!string.IsNullOrEmpty(authorKey))
        {
            authorExternalId = authorKey.Split('/')[^1];
            var author = await http.GetFromJsonAsync<OpenLibraryAuthorResponse>($"{authorKey}.json", cancellationToken);
            authorName = author?.Name;
        }

        var year = ParseYear(work.FirstPublishDate) ?? await FindPublishYearViaSearchAsync(externalId, cancellationToken);
        var (rating, ratingCount) = await GetRatingAsync(externalId, cancellationToken);

        return new BookDetails(
            externalId,
            work.Title ?? string.Empty,
            year,
            ExtractDescription(work.Description),
            authorName,
            authorExternalId,
            work.Subjects.Take(MaxGenres).ToList(),
            BuildCoverUrl(work.Covers.FirstOrDefault()),
            Rating: rating,
            RatingCount: ratingCount);
    }

    /// <summary>
    /// Cross-provider rating fallback (see <see cref="IBookRatingByIsbnLookup"/>): the search index carries
    /// <c>ratings_average</c>/<c>ratings_count</c> directly, so an <c>isbn:</c> query returns the work's
    /// rating in a single call. First hit only, as agreed - a clean resolved ISBN maps to one work. A
    /// 0/absent average is treated as "no rating", not a real zero.
    /// </summary>
    public async Task<(double? Average, int? Count)> GetRatingByIsbnAsync(string isbn, CancellationToken cancellationToken = default)
    {
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>(
            $"search.json?q={Encode($"isbn:{isbn}")}&fields=ratings_average,ratings_count&limit=1", cancellationToken);
        var doc = response?.Docs.FirstOrDefault();
        return doc is { RatingsAverage: > 0 } ? (doc.RatingsAverage, doc.RatingsCount) : (null, null);
    }

    /// <summary>
    /// Open Library exposes a work's aggregate rating on a dedicated <c>/works/{id}/ratings.json</c> endpoint
    /// (not on the work document itself) - one extra call, best-effort: a missing summary just leaves the
    /// book without a reference rating. A 0/absent average is treated as "no rating", not a real zero.
    /// </summary>
    private async Task<(double? Rating, int? Count)> GetRatingAsync(string workKey, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<OpenLibraryRatingsResponse>($"{workKey}/ratings.json", cancellationToken);
        var summary = response?.Summary;
        return summary is { Average: > 0, Count: > 0 } ? (summary.Average, summary.Count) : (null, null);
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
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled, s_regexTimeout);

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

        [JsonPropertyName("ratings_average")]
        public double? RatingsAverage { get; set; }

        [JsonPropertyName("ratings_count")]
        public int? RatingsCount { get; set; }
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

    private sealed class OpenLibraryRatingsResponse
    {
        [JsonPropertyName("summary")]
        public OpenLibraryRatingsSummary? Summary { get; set; }
    }

    private sealed class OpenLibraryRatingsSummary
    {
        [JsonPropertyName("average")]
        public double? Average { get; set; }

        [JsonPropertyName("count")]
        public int Count { get; set; }
    }
}
