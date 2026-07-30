using System.Globalization;
using System.Text.Json.Serialization;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// OMDb REST client - looks up a title by its IMDb id and returns IMDb's own aggregate rating/vote count.
/// Configured as a typed <see cref="HttpClient"/> (see <c>Program.cs</c>), with the api key appended as a
/// query parameter, same convention as <see cref="TmdbClient"/>/<see cref="RawgClient"/>. When no key is
/// configured the client is a graceful no-op (returns <c>null</c>) rather than calling the provider - IMDb
/// enrichment is optional, so a deployment without an OMDb key keeps movies/TV on their TMDB rating alone.
/// </summary>
public class OmdbClient(HttpClient http, OmdbSettings settings) : IOmdbClient
{
    public async Task<OmdbRating?> GetRatingAsync(string imdbId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(settings.ApiKey) || string.IsNullOrEmpty(imdbId)) return null;

        var response = await http.GetFromJsonAsync<OmdbResponse>(
            $"?apikey={settings.ApiKey}&i={Uri.EscapeDataString(imdbId)}", cancellationToken);

        // OMDb returns Response:"False" for an unknown id, and imdbRating:"N/A" for a title nobody has rated -
        // both are "no rating", not a genuine zero (a stored 0 would sort as a real score and render a "0" pill).
        if (response is null || !string.Equals(response.Response, "True", StringComparison.OrdinalIgnoreCase)) return null;
        if (!TryParseRating(response.ImdbRating, out var value)) return null;

        return new OmdbRating(value, ParseVotes(response.ImdbVotes));
    }

    private static bool TryParseRating(string? rating, out double value) =>
        double.TryParse(rating, NumberStyles.Number, CultureInfo.InvariantCulture, out value) && value > 0;

    /// <summary>OMDb formats vote counts with thousands separators ("1,950,000") or "N/A" - strip and parse.</summary>
    private static int? ParseVotes(string? votes) =>
        int.TryParse(votes, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private sealed class OmdbResponse
    {
        [JsonPropertyName("imdbRating")]
        public string? ImdbRating { get; set; }

        [JsonPropertyName("imdbVotes")]
        public string? ImdbVotes { get; set; }

        [JsonPropertyName("Response")]
        public string? Response { get; set; }
    }
}
