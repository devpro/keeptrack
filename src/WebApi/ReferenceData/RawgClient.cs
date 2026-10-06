using System.Globalization;
using System.Text.Json.Serialization;
using System.Web;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// RAWG client, a typed <see cref="HttpClient"/> with the API key as a query parameter, like <see cref="TmdbClient"/>.
/// <para>
/// Not the default game provider (see <see cref="IgdbClient"/>), but registered so an admin can search and link with it, and its <c>rawg</c> and <c>metacritic</c> ratings keep rendering.
/// The background refresh never calls it (see <c>ReferenceEnrichmentService.RefreshVideoGameReferenceAsync</c>).
/// </para>
/// </summary>
public class RawgClient(HttpClient http, RawgSettings settings) : VideoGameReferenceClientBase
{
    public override string ProviderKey => RatingSourceCatalog.Rawg;

    public override string DisplayName => "RAWG";

    /// <summary>RAWG's 0 to 5 user score, its default ordering, and the Metacritic score it republishes.</summary>
    public override IReadOnlyList<string> SupportedRatingSources { get; } = [RatingSourceCatalog.Rawg, RatingSourceCatalog.Metacritic];

    protected override async Task<IReadOnlyList<VideoGameSearchResult>> SearchByRelevanceAsync(string title, int limit, CancellationToken cancellationToken)
    {
        // no `&dates=`, a hard filter on RAWG's release date that would drop a game recorded a year off rather than rank it lower (see VideoGameReferenceClientBase.SearchByRelevanceAsync)
        var query = $"games?key={ApiKey}&search={Encode(title)}&page_size={limit}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new VideoGameSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.Released), r.BackgroundImage)).ToList() ?? [];
    }

    public override async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
    {
        // RAWG has no field equality, and `search_exact=true` only turns off its fuzziness, so near misses still come back.
        // The promised equality is applied here on the response, safe since this is one page, unlike the paging loop, which stops on an empty page.
        var query = $"games?key={ApiKey}&search={Encode(title)}&search_exact=true&page_size={MaxExactTitleResults}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results
            .Where(r => string.Equals(r.Name, title, StringComparison.OrdinalIgnoreCase))
            .Select(r => new VideoGameSearchResult(
                r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.Released), r.BackgroundImage))
            .ToList() ?? [];
    }

    public override async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default)
    {
        if (words.Count == 0) return [];

        // RAWG has no substring operator, `search=` being all it offers, so the promised containment is applied on one page, like FindGamesByExactTitleAsync.
        // Weaker than IGDB's, since RAWG's relevance decides the page, but it costs one call and only returns titles containing every word.
        var query = $"games?key={ApiKey}&search={Encode(string.Join(' ', words))}&page_size={MaxExactTitleResults}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results
            .Where(r => r.Name is not null && words.All(word => r.Name.Contains(word, StringComparison.OrdinalIgnoreCase)))
            .Select(r => new VideoGameSearchResult(
                r.Id.ToString(CultureInfo.InvariantCulture), r.Name!, ParseYear(r.Released), r.BackgroundImage))
            .ToList() ?? [];
    }

    public override async Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default)
    {
        // The detail endpoint accepts the numeric id or the page slug, so a pasted address needs no extra lookup.
        // A 404 is an ordinary "no result" here, hence GetAsync rather than GetFromJsonAsync.
        using var response = await http.GetAsync($"games/{Uri.EscapeDataString(identifier)}?key={ApiKey}", cancellationToken);
        if (!response.IsSuccessStatusCode) return null;

        var details = await response.Content.ReadFromJsonAsync<RawgGameDetailsResponse>(cancellationToken);
        return details is null
            ? null
            : new VideoGameSearchResult(
                details.Id.ToString(CultureInfo.InvariantCulture), details.Name ?? identifier, ParseYear(details.Released), details.BackgroundImage);
    }

    public override async Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<RawgGameDetailsResponse>($"games/{externalId}?key={ApiKey}", cancellationToken);
        return details is null
            ? null
            : new VideoGameDetails(
                externalId, details.Name ?? string.Empty, ParseYear(details.Released), details.DescriptionRaw,
                details.Genres.Select(g => g.Name).ToList(),
                details.Platforms.Select(p => p.Platform?.Name).OfType<string>().ToList(),
                details.BackgroundImage, BuildRatings(details.Rating, details.RatingsCount, details.Metacritic));
    }

    public override async Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        var ordering = ratingSource == RatingSourceCatalog.Metacritic ? "metacritic" : "rating";
        var query = $"games?key={ApiKey}&ordering=-{ordering}&metacritic={MinMetacritic},100&page={page}&page_size={TopRatedPageSize}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new VideoGameTopRatedItem(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? string.Empty, ParseYear(r.Released), r.BackgroundImage,
            BuildRatings(r.Rating, null, r.Metacritic).ToDictionary(x => x.Key, x => x.Value.Value),
            string.IsNullOrEmpty(r.Slug) ? null : ProviderWebLinks.Rawg(r.Slug))).ToList() ?? [];
    }

    /// <summary>
    /// RAWG's two aggregates as a <c>Ratings</c> map: its 0 to 5 user score, and Metacritic's 0 to 100 score when reported, often absent for smaller or older games.
    /// A zero or absent value means no rating and is omitted, never stored as zero.
    /// </summary>
    private static Dictionary<string, ReferenceRatingModel> BuildRatings(double? rating, int? ratingsCount, int? metacritic)
    {
        var ratings = new Dictionary<string, ReferenceRatingModel>();
        if (rating is > 0)
        {
            ratings[RatingSourceCatalog.Rawg] = new ReferenceRatingModel { Value = rating.Value, Scale = 5, Count = ratingsCount };
        }
        if (metacritic is > 0)
        {
            ratings[RatingSourceCatalog.Metacritic] = new ReferenceRatingModel { Value = metacritic.Value, Scale = 100 };
        }
        return ratings;
    }

    /// <summary>Bound of <see cref="FindGamesByExactTitleAsync"/> (see <c>IgdbClient</c> for why it is the larger one).</summary>
    private const int MaxExactTitleResults = 40;

    /// <summary>RAWG's maximum page size, so discovery needs as few round trips as possible.</summary>
    private const int TopRatedPageSize = 40;

    /// <summary>
    /// Notability floor of the discovery pool: only games Metacritic rates "generally favorable" or better, whatever score orders the list.
    /// RAWG has no curated top-rated list like TMDB's, and its <c>rating</c> is a plain average with no vote-count filter, so ordering by it would rank a game with a single 5-star vote above every classic.
    /// Requiring a press score is the closest server-side equivalent of TMDB's vote threshold, at no extra call.
    /// </summary>
    private const int MinMetacritic = 60;

    private string ApiKey => settings.ApiKey;

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    private static int? ParseYear(string? date) =>
        !string.IsNullOrEmpty(date) && DateOnly.TryParse(date, CultureInfo.InvariantCulture, out var parsed) ? parsed.Year : null;

    private sealed class RawgSearchResponse
    {
        [JsonPropertyName("results")]
        public List<RawgSearchItem> Results { get; set; } = [];
    }

    private sealed class RawgSearchItem
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("released")]
        public string? Released { get; set; }

        [JsonPropertyName("background_image")]
        public string? BackgroundImage { get; set; }

        // read only by the top-rated listing, every /games query returning the same shape
        [JsonPropertyName("rating")]
        public double? Rating { get; set; }

        [JsonPropertyName("metacritic")]
        public int? Metacritic { get; set; }

        /// <summary>What rawg.io keys a game's page on, which <see cref="Id"/> cannot be turned into.</summary>
        [JsonPropertyName("slug")]
        public string? Slug { get; set; }
    }

    private sealed class RawgGameDetailsResponse
    {
        [JsonPropertyName("id")]
        public long Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("released")]
        public string? Released { get; set; }

        [JsonPropertyName("description_raw")]
        public string? DescriptionRaw { get; set; }

        [JsonPropertyName("background_image")]
        public string? BackgroundImage { get; set; }

        [JsonPropertyName("rating")]
        public double? Rating { get; set; }

        [JsonPropertyName("ratings_count")]
        public int? RatingsCount { get; set; }

        [JsonPropertyName("metacritic")]
        public int? Metacritic { get; set; }

        [JsonPropertyName("genres")]
        public List<RawgGenre> Genres { get; set; } = [];

        [JsonPropertyName("platforms")]
        public List<RawgPlatformWrapper> Platforms { get; set; } = [];
    }

    private sealed class RawgGenre
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
    }

    private sealed class RawgPlatformWrapper
    {
        [JsonPropertyName("platform")]
        public RawgPlatform? Platform { get; set; }
    }

    private sealed class RawgPlatform
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}
