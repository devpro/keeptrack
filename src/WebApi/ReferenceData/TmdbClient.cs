using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// TMDB v3 REST client. The first server-side outbound third-party HTTP call in the repo - configured
/// as a typed <see cref="HttpClient"/> (see <c>Program.cs</c>), with the api key appended as a query
/// parameter on every request, matching TMDB's v3 authentication scheme.
/// </summary>
public class TmdbClient(HttpClient http, TmdbSettings settings) : ITmdbClient
{
    public async Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"search/tv?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&first_air_date_year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.FirstAirDate), r.Overview)).ToList() ?? [];
    }

    public async Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"search/movie?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Title ?? title, ParseYear(r.ReleaseDate), r.Overview)).ToList() ?? [];
    }

    public async Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<TmdbTvShowDetailsResponse>($"tv/{tmdbId}?api_key={ApiKey}", cancellationToken);
        if (details is null) return null;

        var episodes = new List<TmdbEpisode>();
        foreach (var season in details.Seasons.Where(s => s.SeasonNumber > 0))
        {
            var seasonDetails = await http.GetFromJsonAsync<TmdbSeasonDetailsResponse>(
                $"tv/{tmdbId}/season/{season.SeasonNumber}?api_key={ApiKey}", cancellationToken);
            if (seasonDetails is null) continue;

            episodes.AddRange(seasonDetails.Episodes.Select(e =>
                new TmdbEpisode(season.SeasonNumber, e.EpisodeNumber, e.Name ?? $"Episode {e.EpisodeNumber}", ParseDate(e.AirDate))));
        }

        return new TmdbTvShowDetails(tmdbId, details.Name ?? string.Empty, ParseYear(details.FirstAirDate), details.Overview, episodes);
    }

    public async Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<TmdbMovieDetailsResponse>($"movie/{tmdbId}?api_key={ApiKey}", cancellationToken);
        return details is null
            ? null
            : new TmdbMovieDetails(tmdbId, details.Title ?? string.Empty, ParseYear(details.ReleaseDate), details.Overview);
    }

    private string ApiKey => settings.ApiKey;

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    private static int? ParseYear(string? date) => ParseDate(date)?.Year;

    private static DateOnly? ParseDate(string? date) =>
        !string.IsNullOrEmpty(date) && DateOnly.TryParse(date, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private sealed class TmdbSearchResponse
    {
        [JsonPropertyName("results")]
        public List<TmdbSearchItem> Results { get; set; } = [];
    }

    private sealed class TmdbSearchItem
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("overview")]
        public string? Overview { get; set; }

        [JsonPropertyName("first_air_date")]
        public string? FirstAirDate { get; set; }

        [JsonPropertyName("release_date")]
        public string? ReleaseDate { get; set; }
    }

    private sealed class TmdbTvShowDetailsResponse
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("overview")]
        public string? Overview { get; set; }

        [JsonPropertyName("first_air_date")]
        public string? FirstAirDate { get; set; }

        [JsonPropertyName("seasons")]
        public List<TmdbSeasonSummary> Seasons { get; set; } = [];
    }

    private sealed class TmdbSeasonSummary
    {
        [JsonPropertyName("season_number")]
        public int SeasonNumber { get; set; }
    }

    private sealed class TmdbSeasonDetailsResponse
    {
        [JsonPropertyName("episodes")]
        public List<TmdbEpisodeWire> Episodes { get; set; } = [];
    }

    private sealed class TmdbEpisodeWire
    {
        [JsonPropertyName("episode_number")]
        public int EpisodeNumber { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("air_date")]
        public string? AirDate { get; set; }
    }

    private sealed class TmdbMovieDetailsResponse
    {
        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("overview")]
        public string? Overview { get; set; }

        [JsonPropertyName("release_date")]
        public string? ReleaseDate { get; set; }
    }
}
