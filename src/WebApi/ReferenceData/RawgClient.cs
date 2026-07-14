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
                details.BackgroundImage);
    }

    private const int MaxResults = 5;

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
