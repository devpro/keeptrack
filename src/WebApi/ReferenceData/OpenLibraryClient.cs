using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Open Library client, keyless, a typed <see cref="HttpClient"/> with the descriptive User-Agent Open Library asks for.
/// </summary>
public class OpenLibraryClient(HttpClient http) : BookReferenceClientBase, IBookRatingByIsbnLookup
{
    public override string ProviderKey => "openlibrary";

    public override string DisplayName => "Open Library";

    private static readonly TimeSpan s_regexTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The search index answers an <c>isbn:</c> query with the work the edition belongs to, in one call like <see cref="GetRatingByIsbnAsync"/>, reading the display fields instead.
    /// <c>q=isbn:9782265002104</c> returns one work with title, year, authors and cover, a French edition BnF does not hold.
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken) =>
        RunSearchAsync($"search.json?q={Encode($"isbn:{isbn}")}", null, cancellationToken);

    /// <summary>
    /// A relevance query (<c>q=</c>), not <c>title=</c>, which only matches a work's canonical title and misses regional variants.
    /// <c>title=</c> finds only empty stubs for "Harry Potter and the Sorcerer's Stone", the canonical work being "Harry Potter and the Philosopher's Stone", which <c>q=</c> ranks first.
    /// <para>
    /// No year is sent, since <c>first_publish_year</c> is the work's original year, which differs from the edition a tenant records (a 1997 first edition, a 2016 reprint), so filtering would drop the real match.
    /// </para>
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken) =>
        RunSearchAsync(
            $"search.json?q={Encode(title)}" + (string.IsNullOrEmpty(author) ? "" : $"&author={Encode(author)}"),
            title,
            cancellationToken);

    /// <summary>
    /// <paramref name="titleFallback"/> is the searched text, used when a match has no title, only on the title path, so an ISBN search drops a titleless stub rather than labelling it with the ISBN.
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
    /// The rating fallback (see <see cref="IBookRatingByIsbnLookup"/>): the search index carries <c>ratings_average</c> and <c>ratings_count</c>, so an <c>isbn:</c> query returns the rating in one call.
    /// The first hit only, since a resolved ISBN maps to one work.
    /// A zero or absent average means no rating.
    /// </summary>
    public async Task<(double? Average, int? Count)> GetRatingByIsbnAsync(string isbn, CancellationToken cancellationToken = default)
    {
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>(
            $"search.json?q={Encode($"isbn:{isbn}")}&fields=ratings_average,ratings_count&limit=1", cancellationToken);
        var doc = response?.Docs.FirstOrDefault();
        return doc is { RatingsAverage: > 0 } ? (doc.RatingsAverage, doc.RatingsCount) : (null, null);
    }

    /// <summary>
    /// A work's rating comes from <c>/works/{id}/ratings.json</c>, not the work document: one extra call, best effort, a missing summary leaving the book unrated.
    /// A zero or absent average means no rating.
    /// </summary>
    private async Task<(double? Rating, int? Count)> GetRatingAsync(string workKey, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<OpenLibraryRatingsResponse>($"{workKey}/ratings.json", cancellationToken);
        var summary = response?.Summary;
        return summary is { Average: > 0, Count: > 0 } ? (summary.Average, summary.Count) : (null, null);
    }

    /// <summary>
    /// Falls back to the search index's <c>first_publish_year</c> when the work has no <c>first_publish_date</c>, common even for known books (Lee Child's "Killing Floor").
    /// A query scoped to the one work (<c>q=key:{workKey}</c>), not a title search.
    /// </summary>
    private async Task<int?> FindPublishYearViaSearchAsync(string workKey, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<OpenLibrarySearchResponse>($"search.json?q={Encode($"key:{workKey}")}", cancellationToken);
        return response?.Docs.FirstOrDefault()?.FirstPublishYear;
    }

    /// <summary>
    /// A work's <c>description</c> is a plain string or an object <c>{ "type": "/type/text", "value": "..." }</c>, both read here, so the wire model stays a <see cref="JsonElement"/> rather than needing a converter.
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
    /// Matches a standalone 4-digit token, since <c>first_publish_date</c> is often "Month Day, Year" ("November 12, 1972"), where the first four digits would read 1219.
    /// The year is the last such token, trailing the day and month, or the only one in a bare year.
    /// </summary>
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled, s_regexTimeout);

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var matches = s_yearRegex.Matches(date);
        return matches.Count > 0 && int.TryParse(matches[^1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }

    /// <summary>
    /// Open Library's cover CDN is an unauthenticated host meant for hotlinking, like TMDB's.
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
