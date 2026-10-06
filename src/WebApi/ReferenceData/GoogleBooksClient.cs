using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

public partial class GoogleBooksClient(HttpClient http, GoogleBooksSettings settings) : BookReferenceClientBase
{
    public override string ProviderKey => "googlebooks";

    public override string DisplayName => "Google Books";

    private const int MaxResults = 20;

    private const int MaxGenres = 5;

    private string ApiKey => settings.ApiKey;

    /// <summary>
    /// An ISBN is an exact identifier, so it is the sole query, since combining it with a fuzzy title could only lose matches.
    /// <see cref="BookReferenceClientBase.SearchBooksAsync"/> decides whether a miss widens to a title search.
    /// </summary>
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByIsbnAsync(string isbn, CancellationToken cancellationToken) =>
        SearchBooksCoreAsync($"isbn:{isbn}", cancellationToken);

    /// <inheritdoc />
    protected override Task<IReadOnlyList<BookSearchResult>> SearchByTitleAsync(string title, string? author, CancellationToken cancellationToken) =>
        SearchBooksCoreAsync(BuildQuery(title, author), cancellationToken);

    /// <summary>
    /// Google's <c>fields=</c> partial response (https://developers.google.com/books/docs/v1/performance), restricted to what <see cref="BookSearchResult"/> reads.
    /// The unfiltered response is about 75KB for 20 results, each with a whole <c>volumeInfo</c>, against 14KB for a TMDB movie search, which made Google Books the slowest provider.
    /// </summary>
    private const string SearchFields = "fields=items(id,volumeInfo(title,authors,publishedDate,imageLinks/thumbnail))";

    /// <summary>
    /// Like <see cref="SearchFields"/>, restricted to what <see cref="BookDetails"/> reads.
    /// </summary>
    private const string DetailsFields = "fields=volumeInfo(title,publishedDate,description,authors,categories,imageLinks/thumbnail,language,industryIdentifiers,averageRating,ratingsCount)";

    private async Task<IReadOnlyList<BookSearchResult>> SearchBooksCoreAsync(string query, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<GoogleBooksSearchResponse>(
            $"volumes?q={Encode(query)}&maxResults={MaxResults}&key={ApiKey}&{SearchFields}", cancellationToken);

        return response?.Items
            .Where(i => !string.IsNullOrEmpty(i.Id) && !string.IsNullOrEmpty(i.VolumeInfo?.Title))
            .Select(i => new BookSearchResult(i.Id!, i.VolumeInfo!.Title!, ParseYear(i.VolumeInfo.PublishedDate), i.VolumeInfo.Authors.FirstOrDefault(),
                BuildImageUrl(i.VolumeInfo.ImageLinks)))
            .ToList() ?? [];
    }

    public override async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var volume = await http.GetFromJsonAsync<GoogleBooksVolume>($"volumes/{externalId}?key={ApiKey}&{DetailsFields}", cancellationToken);
        var info = volume?.VolumeInfo;
        if (info?.Title is null) return null;

        return new BookDetails(
            externalId,
            info.Title,
            ParseYear(info.PublishedDate),
            CleanDescription(info.Description),
            info.Authors.FirstOrDefault(),
            null,
            info.Categories.Take(MaxGenres).ToList(),
            BuildImageUrl(info.ImageLinks),
            info.Language,
            ExtractIsbn(info.IndustryIdentifiers),
            info.AverageRating,
            info.RatingsCount);
    }

    private static string BuildQuery(string title, string? author)
    {
        var q = $"intitle:{title}";
        return string.IsNullOrEmpty(author) ? q : $"{q} inauthor:{author}";
    }

    /// <summary>
    /// Prefers ISBN_13, the current standard, over ISBN_10 when a volume reports both.
    /// </summary>
    private static string? ExtractIsbn(List<GoogleBooksIndustryIdentifier> identifiers)
    {
        return identifiers.FirstOrDefault(i => i.Type == "ISBN_13")?.Identifier
               ?? identifiers.FirstOrDefault(i => i.Type == "ISBN_10")?.Identifier;
    }

    private static string Encode(string value)
    {
        return HttpUtility.UrlEncode(value);
    }

    /// <summary>
    /// Matches a standalone 4-digit token, since <c>volumeInfo.publishedDate</c> has no fixed format (a bare year, "YYYY-MM" or "YYYY-MM-DD"), as <see cref="OpenLibraryClient"/> parses years.
    /// </summary>
    [GeneratedRegex(@"\b\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex YearRegex();
    private static readonly Regex s_yearRegex = YearRegex();

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var match = s_yearRegex.Match(date);
        return match.Success && int.TryParse(match.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }

    /// <summary>
    /// <c>volumeInfo.description</c> is HTML with "simple formatting elements, such as b, i, and br tags".
    /// Entities are decoded first, so an encoded tag (<c>&amp;lt;script&amp;gt;</c>) cannot survive the strip and become a real tag afterward.
    /// Only bare <c>&lt;b&gt;</c>, <c>&lt;i&gt;</c> and <c>&lt;br/&gt;</c> tags are then rebuilt from their name, attributes discarded, and every other tag removed.
    /// That fixed allowlist is what makes rendering the result as a <c>MarkupString</c> on <c>BookDetail.razor</c> safe: no attribute such as <c>onclick</c> can survive.
    /// </summary>
    [GeneratedRegex(@"</?(\w+)\b[^>]*>", RegexOptions.Compiled)]
    private static partial Regex TagRegex();
    private static readonly Regex s_tagRegex = TagRegex();

    /// <summary>
    /// Descriptions also break paragraphs with plain newlines, which HTML collapses, so a description without <c>&lt;br&gt;</c> tags would render as one paragraph.
    /// They become <c>&lt;br/&gt;</c> before the tag pass, so they go through the same allowlist as any other.
    /// </summary>
    [GeneratedRegex(@"\r\n|\r|\n", RegexOptions.Compiled)]
    private static partial Regex NewLineRegex();
    private static readonly Regex s_newlineRegex = NewLineRegex();

    private static string? CleanDescription(string? html)
    {
        if (string.IsNullOrEmpty(html)) return null;

        var decoded = s_newlineRegex.Replace(WebUtility.HtmlDecode(html), "<br/>");
        var text = s_tagRegex.Replace(decoded, m =>
        {
            var isClosing = m.Value.StartsWith("</", StringComparison.Ordinal);
            return m.Groups[1].Value.ToLowerInvariant() switch
            {
                "b" => isClosing ? "</b>" : "<b>",
                "i" => isClosing ? "</i>" : "<i>",
                "br" => "<br/>",
                _ => ""
            };
        }).Trim();

        return text.Length == 0 ? null : text;
    }

    /// <summary>
    /// Google Books returns thumbnails as plain <c>http://</c>, upgraded to <c>https://</c> so the app's HTTPS pages do not block them as mixed content.
    /// </summary>
    private static string? BuildImageUrl(GoogleBooksImageLinks? imageLinks)
    {
        return string.IsNullOrEmpty(imageLinks?.Thumbnail) ? null : imageLinks.Thumbnail.Replace("http://", "https://", StringComparison.Ordinal);
    }

    private sealed class GoogleBooksSearchResponse
    {
        [JsonPropertyName("items")]
        public List<GoogleBooksVolume> Items { get; set; } = [];
    }

    private sealed class GoogleBooksVolume
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("volumeInfo")]
        public GoogleBooksVolumeInfo? VolumeInfo { get; set; }
    }

    private sealed class GoogleBooksVolumeInfo
    {
        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("authors")]
        public List<string> Authors { get; set; } = [];

        [JsonPropertyName("publishedDate")]
        public string? PublishedDate { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("categories")]
        public List<string> Categories { get; set; } = [];

        [JsonPropertyName("language")]
        public string? Language { get; set; }

        [JsonPropertyName("averageRating")]
        public double? AverageRating { get; set; }

        [JsonPropertyName("ratingsCount")]
        public int? RatingsCount { get; set; }

        [JsonPropertyName("imageLinks")]
        public GoogleBooksImageLinks? ImageLinks { get; set; }

        [JsonPropertyName("industryIdentifiers")]
        public List<GoogleBooksIndustryIdentifier> IndustryIdentifiers { get; set; } = [];
    }

    private sealed class GoogleBooksImageLinks
    {
        [JsonPropertyName("thumbnail")]
        public string? Thumbnail { get; set; }
    }

    private sealed class GoogleBooksIndustryIdentifier
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("identifier")]
        public string? Identifier { get; set; }
    }
}
