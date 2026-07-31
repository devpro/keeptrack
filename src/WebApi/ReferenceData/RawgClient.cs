using System.Globalization;
using System.Text.Json.Serialization;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// RAWG Video Games Database REST client. Configured as a typed <see cref="HttpClient"/> (see Program.cs),
/// with the api key appended as a query parameter on every request, same convention as <see cref="TmdbClient"/>.
/// </summary>
public class RawgClient(HttpClient http, RawgSettings settings) : IRawgClient
{
    public async Task<IReadOnlyList<RawgSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"games?key={ApiKey}&search={Encode(title)}&page_size={MaxResults}" + (year is null ? "" : $"&dates={year}-01-01,{year}-12-31");
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new RawgSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.Released), r.BackgroundImage)).ToList() ?? [];
    }

    public async Task<RawgGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<RawgGameDetailsResponse>($"games/{externalId}?key={ApiKey}", cancellationToken);
        return details is null
            ? null
            : new RawgGameDetails(
                externalId, details.Name ?? string.Empty, ParseYear(details.Released), details.DescriptionRaw,
                details.Genres.Select(g => g.Name).ToList(),
                details.Platforms.Select(p => p.Platform?.Name).OfType<string>().ToList(),
                details.BackgroundImage, details.Rating, details.RatingsCount, details.Metacritic);
    }

    public async Task<IReadOnlyList<RawgTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        var ordering = ratingSource == RatingSourceCatalog.Metacritic ? "metacritic" : "rating";
        var query = $"games?key={ApiKey}&ordering=-{ordering}&metacritic={MinMetacritic},100&page={page}&page_size={TopRatedPageSize}";
        var response = await http.GetFromJsonAsync<RawgSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new RawgTopRatedItem(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? string.Empty, ParseYear(r.Released), r.BackgroundImage,
            r.Rating, r.Metacritic)).ToList() ?? [];
    }

    private const int MaxResults = 5;

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
    private const int MinMetacritic = 70;

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
