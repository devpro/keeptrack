using System.Globalization;
using System.Net;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Google Books REST client - the default book provider (<c>ReferenceData:BookProvider</c>, see Program.cs)
/// once it's registered, chosen over Open Library/BnF for real synopses, cover art, language and much wider
/// catalogue coverage (including manga/comics), which the other two were both found lacking in practice.
/// Registered as a typed <see cref="HttpClient"/> with the API key appended as a query parameter, same
/// convention as <see cref="RawgClient"/>/<see cref="TmdbClient"/> - see Program.cs.
/// </summary>
public class GoogleBooksClient(HttpClient http, GoogleBooksSettings settings) : IBookReferenceClient
{
    public string ProviderKey => "googlebooks";

    public string DisplayName => "Google Books";

    private const int MaxResults = 20;

    private const int MaxGenres = 5;

    private string ApiKey => settings.ApiKey;

    public async Task<IReadOnlyList<BookSearchResult>> SearchBooksAsync(string title, int? year, string? author = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchBooksCoreAsync(title, author, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(author))
        {
            // same "an optional narrowing parameter must never silently zero out results" lesson as
            // OpenLibraryClient/DiscogsClient/BnfClient - an "inauthor:" qualifier that doesn't exactly
            // match Google's own indexing can zero out results the title alone would find.
            results = await SearchBooksCoreAsync(title, null, cancellationToken);
        }

        return results;
    }

    private async Task<IReadOnlyList<BookSearchResult>> SearchBooksCoreAsync(string title, string? author, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<GoogleBooksSearchResponse>(
            $"volumes?q={Encode(BuildQuery(title, author))}&maxResults={MaxResults}&key={ApiKey}", cancellationToken);

        return response?.Items
            .Where(i => !string.IsNullOrEmpty(i.Id) && !string.IsNullOrEmpty(i.VolumeInfo?.Title))
            .Select(i => new BookSearchResult(i.Id!, i.VolumeInfo!.Title!, ParseYear(i.VolumeInfo.PublishedDate), i.VolumeInfo.Authors.FirstOrDefault(), BuildImageUrl(i.VolumeInfo.ImageLinks)))
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
            info.Language);
    }

    private static string BuildQuery(string title, string? author)
    {
        var q = $"intitle:{title}";
        return string.IsNullOrEmpty(author) ? q : $"{q} inauthor:{author}";
    }

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    /// <summary>
    /// Matches a standalone 4-digit token - <c>volumeInfo.publishedDate</c> is documented as a plain string
    /// with no fixed format (seen in practice as a bare year, "YYYY-MM", or "YYYY-MM-DD"), same defensive
    /// approach as <see cref="OpenLibraryClient"/>'s own year parsing rather than a bare <c>int.Parse</c>.
    /// </summary>
    private static readonly Regex s_yearRegex = new(@"\b\d{4}\b", RegexOptions.Compiled);

    private static int? ParseYear(string? date)
    {
        if (string.IsNullOrEmpty(date)) return null;
        var match = s_yearRegex.Match(date);
        return match.Success && int.TryParse(match.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var year) ? year : null;
    }

    /// <summary>
    /// <c>volumeInfo.description</c> is documented as HTML-formatted ("simple formatting elements, such as
    /// b, i, and br tags"), not plain text - rendered as-is, an admin would see literal escaped tags in the
    /// search results/synopsis instead of formatted text. Strips tags and decodes entities down to plain text.
    /// </summary>
    private static string? CleanDescription(string? html)
    {
        if (string.IsNullOrEmpty(html)) return null;

        var withoutBreaks = Regex.Replace(html, "<br\\s*/?>", " ", RegexOptions.IgnoreCase);
        var withoutTags = Regex.Replace(withoutBreaks, "<[^>]+>", "");
        var text = WebUtility.HtmlDecode(withoutTags).Trim();
        return text.Length == 0 ? null : text;
    }

    /// <summary>
    /// Google Books' own thumbnail URLs are widely documented (across its API consumer ecosystem) to come
    /// back as plain <c>http://</c> - upgraded to <c>https://</c> here so embedding it in this app's own
    /// HTTPS pages doesn't trip mixed-content blocking, the same reasoning TMDB/Open Library's own
    /// always-https CDN URLs never need applied to them.
    /// </summary>
    private static string? BuildImageUrl(GoogleBooksImageLinks? imageLinks) =>
        string.IsNullOrEmpty(imageLinks?.Thumbnail) ? null : imageLinks.Thumbnail.Replace("http://", "https://", StringComparison.Ordinal);

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
    }

    private sealed class GoogleBooksImageLinks
    {
        [JsonPropertyName("thumbnail")]
        public string? Thumbnail { get; set; }
    }
}
