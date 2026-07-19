using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Google Books REST client.
/// </summary>
public partial class GoogleBooksClient(HttpClient http, GoogleBooksSettings settings) : IBookReferenceClient
{
    public string ProviderKey => "googlebooks";

    public string DisplayName => "Google Books";

    private const int MaxResults = 20;

    private const int MaxGenres = 5;

    private string ApiKey => settings.ApiKey;

    public async Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, string? isbn = null,
        CancellationToken cancellationToken = default)
    {
        // an ISBN is an exact identifier
        // when supplied it supersedes title/author entirely rather than being combined with them
        // since combining risks the same "and" narrowing correctness a plain identifier lookup doesn't need to worry about
        if (!string.IsNullOrEmpty(isbn)) return await SearchBooksCoreAsync($"isbn:{isbn}", cancellationToken);

        var results = await SearchBooksCoreAsync(BuildQuery(title, author), cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // an optional narrowing parameter must never silently zero out results
            // an "inauthor:" qualifier that doesn't exactly match Google's own indexing can zero out results the title alone would find
            results = await SearchBooksCoreAsync(BuildQuery(title, null), cancellationToken);
        }

        return results;
    }

    private async Task<IReadOnlyList<BookSearchResult>> SearchBooksCoreAsync(string query, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<GoogleBooksSearchResponse>(
            $"volumes?q={Encode(query)}&maxResults={MaxResults}&key={ApiKey}", cancellationToken);

        return response?.Items
            .Where(i => !string.IsNullOrEmpty(i.Id) && !string.IsNullOrEmpty(i.VolumeInfo?.Title))
            .Select(i => new BookSearchResult(i.Id!, i.VolumeInfo!.Title!, ParseYear(i.VolumeInfo.PublishedDate), i.VolumeInfo.Authors.FirstOrDefault(),
                BuildImageUrl(i.VolumeInfo.ImageLinks)))
            .ToList() ?? [];
    }

    public async Task<BookDetails?> GetBookDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var volume = await http.GetFromJsonAsync<GoogleBooksVolume>($"volumes/{externalId}?key={ApiKey}", cancellationToken);
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
            ExtractIsbn(info.IndustryIdentifiers));
    }

    private static string BuildQuery(string title, string? author)
    {
        var q = $"intitle:{title}";
        return string.IsNullOrEmpty(author) ? q : $"{q} inauthor:{author}";
    }

    /// <summary>
    /// Prefers ISBN_13 (the current standard) over ISBN_10 when a volume reports both
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
    /// Matches a standalone 4-digit token
    /// <c>volumeInfo.publishedDate</c> is documented as a plain string with no fixed format (seen in practice as a bare year, "YYYY-MM", or "YYYY-MM-DD")
    /// same defensive approach as <see cref="OpenLibraryClient"/>'s own year parsing rather than a bare <c>int.Parse</c>.
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
    /// <c>volumeInfo.description</c> is documented as HTML-formatted ("simple formatting elements, such as
    /// b, i, and br tags") - decodes entities first (so an entity-encoded tag, e.g. <c>&amp;lt;script&amp;gt;</c>,
    /// can't survive the strip below and only turn into a real tag afterward), then keeps only bare,
    /// attribute-free <c>&lt;b&gt;</c>/<c>&lt;i&gt;</c>/<c>&lt;br/&gt;</c> tags - reconstructed from just the
    /// tag name, discarding any attributes the original tag carried - and removes every other tag entirely.
    /// This fixed allowlist-and-reconstruct approach (not a general sanitizer) is specifically what makes it
    /// safe to render the result as <c>MarkupString</c> on <c>BookDetail.razor</c>: nothing but those three
    /// bare tags can ever survive, so there's no attribute-based injection vector (e.g. a stray
    /// <c>onclick</c>) to worry about.
    /// </summary>
    [GeneratedRegex(@"</?(\w+)\b[^>]*>", RegexOptions.Compiled)]
    private static partial Regex TagRegex();
    private static readonly Regex s_tagRegex = TagRegex();

    /// <summary>
    /// Real descriptions confirmed to also use plain newline characters for paragraph breaks, not just <c>&lt;br&gt;</c> tags
    /// a description with only bold/italic markup and no actual <c>&lt;br&gt;</c> tags otherwise renders as one massive paragraph
    /// since HTML collapses bare newlines to whitespace.
    /// Converted to real <c>&lt;br/&gt;</c> tags before the tag pass above (rather than a separate step after),
    /// so it goes through the exact same allowlist reconstruction as any other <c>&lt;br&gt;</c>.
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
    /// Google Books' own thumbnail URLs are widely documented (across its API consumer ecosystem) to come back as plain <c>http://</c> -
    /// upgraded to <c>https://</c> here so embedding it in this app's own HTTPS pages doesn't trip mixed-content blocking,
    /// the same reasoning TMDB/Open Library's own always-https CDN URLs never need applied to them.
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
