using System.Globalization;
using System.Text.Json.Serialization;
using System.Web;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// RAWG Video Games Database REST client. Configured as a typed <see cref="HttpClient"/> (see Program.cs),
/// with the api key appended as a query parameter on every request, same convention as <see cref="TmdbClient"/>.
/// <para>
/// No longer the default video game provider (see <see cref="IgdbClient"/>) but deliberately still registered,
/// for two reasons: an admin can still search and link with it, and the <c>rawg</c>/<c>metacritic</c> ratings it
/// already produced stay on those reference documents and keep rendering.
/// It is *not* called by the background refresh - see
/// <c>ReferenceEnrichmentService.RefreshVideoGameReferenceAsync</c> for why only the default provider is.
/// </para>
/// </summary>
public class RawgClient(HttpClient http, RawgSettings settings) : IVideoGameReferenceClient
{
    public string ProviderKey => RatingSourceCatalog.Rawg;

    public string DisplayName => "RAWG";

    /// <summary>RAWG's own 0-5 user score (its default ordering) and the Metacritic score it republishes.</summary>
    public IReadOnlyList<string> SupportedRatingSources { get; } = [RatingSourceCatalog.Rawg, RatingSourceCatalog.Metacritic];

    public async Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"games?key={ApiKey}&search={Encode(title)}&page_size={MaxResults}" + (year is null ? "" : $"&dates={year}-01-01,{year}-12-31");
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new VideoGameSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.Released), r.BackgroundImage)).ToList() ?? [];
    }

    public async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
    {
        // RAWG has no equality operator on a field; `search_exact=true` only turns *off* the fuzziness of its
        // relevance search, so it narrows the pool but still returns near-misses. The equality this method
        // promises its callers is therefore applied here, on the response - a filter the paging loop's
        // "an empty page ends the walk" rule makes unsafe elsewhere in this client, but this is a single page.
        var query = $"games?key={ApiKey}&search={Encode(title)}&search_exact=true&page_size={MaxExactTitleResults}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results
            .Where(r => string.Equals(r.Name, title, StringComparison.OrdinalIgnoreCase))
            .Select(r => new VideoGameSearchResult(
                r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.Released), r.BackgroundImage))
            .ToList() ?? [];
    }

    public async Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default)
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

    public async Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        var ordering = ratingSource == RatingSourceCatalog.Metacritic ? "metacritic" : "rating";
        var query = $"games?key={ApiKey}&ordering=-{ordering}&metacritic={MinMetacritic},100&page={page}&page_size={TopRatedPageSize}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new VideoGameTopRatedItem(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? string.Empty, ParseYear(r.Released), r.BackgroundImage,
            BuildRatings(r.Rating, null, r.Metacritic).ToDictionary(x => x.Key, x => x.Value.Value))).ToList() ?? [];
    }

    /// <summary>
    /// RAWG's two aggregates as a <c>Ratings</c> map: its own 0-5 user score plus Metacritic's 0-100 critic
    /// score when it reports one (frequently absent for smaller/older games). A 0/absent value is treated as
    /// "no rating" and omitted, never stored as a genuine zero.
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

    private const int MaxResults = 5;

    /// <summary>Bound on <see cref="FindGamesByExactTitleAsync"/> - see <c>IgdbClient</c>'s own on why it is the larger one.</summary>
    private const int MaxExactTitleResults = 40;

    /// <summary>RAWG's per-page maximum, so a discovery request needs as few round-trips as possible.</summary>
    private const int TopRatedPageSize = 40;

    /// <summary>
    /// Notability floor on the discovery pool: only games Metacritic rates "generally favorable" or better are
    /// candidates, whichever score the list is then *ordered* by. RAWG has no curated top-rated endpoint like
    /// TMDB's (whose own list already applies a minimum vote count), and its <c>rating</c> is a plain average
    /// with no vote-count filter or sort option - so ordering the whole ~900k-game catalogue by <c>-rating</c>
    /// would rank an unknown game carrying a single 5-star vote above every classic. Requiring a Metacritic
    /// score (i.e. the game was reviewed by the professional press at all) is the closest server-side
    /// equivalent of TMDB's vote threshold, and it costs no extra call. Raise it for a stricter list.
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

        // only populated on the top-rated listing (the search path ignores both) - RAWG's list serializer
        // returns the same shape for every /games query.
        [JsonPropertyName("rating")]
        public double? Rating { get; set; }

        [JsonPropertyName("metacritic")]
        public int? Metacritic { get; set; }
    }

    private sealed class RawgGameDetailsResponse
    {
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
