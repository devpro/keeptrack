using System.Globalization;
using System.Text.Json.Serialization;
using System.Web;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// TMDB v3 REST client. The first server-side outbound third-party HTTP call in the repo -
/// configured as a typed <see cref="HttpClient"/> (see <c>Program.cs</c>),
/// with the api key appended as a query parameter on every request, matching TMDB's v3 authentication scheme.
/// </summary>
public class TmdbClient(HttpClient http, TmdbSettings settings) : ITmdbClient
{
    public async Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"search/tv?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&first_air_date_year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.FirstAirDate), r.Overview, BuildImageUrl(r.PosterPath, PosterImageSize))).ToList() ?? [];
    }

    public async Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"search/movie?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Title ?? title, ParseYear(r.ReleaseDate), r.Overview, BuildImageUrl(r.PosterPath, PosterImageSize))).ToList() ?? [];
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

        return new TmdbTvShowDetails(
            tmdbId, details.Name ?? string.Empty, ParseYear(details.FirstAirDate), details.Overview, episodes,
            details.Genres.Select(g => g.Name).ToList(), BuildImageUrl(details.PosterPath, PosterImageSize));
    }

    public async Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<TmdbMovieDetailsResponse>($"movie/{tmdbId}?api_key={ApiKey}", cancellationToken);
        return details is null
            ? null
            : new TmdbMovieDetails(
                tmdbId, details.Title ?? string.Empty, ParseYear(details.ReleaseDate), details.Overview,
                details.Genres.Select(g => g.Name).ToList(), BuildImageUrl(details.PosterPath, PosterImageSize));
    }

    public async Task<IReadOnlyList<TmdbCastMember>> GetTvShowCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
        await GetCastAsync($"tv/{tmdbId}/credits", cancellationToken);

    public async Task<IReadOnlyList<TmdbCastMember>> GetMovieCastAsync(string tmdbId, CancellationToken cancellationToken = default) =>
        await GetCastAsync($"movie/{tmdbId}/credits", cancellationToken);

    private async Task<IReadOnlyList<TmdbCastMember>> GetCastAsync(string path, CancellationToken cancellationToken)
    {
        var credits = await http.GetFromJsonAsync<TmdbCreditsResponse>($"{path}?api_key={ApiKey}", cancellationToken);
        return credits?.Cast.Select(c => new TmdbCastMember(
            c.Id.ToString(CultureInfo.InvariantCulture), c.Name ?? string.Empty, c.Character ?? string.Empty, c.Order,
            BuildImageUrl(c.ProfilePath, ProfileImageSize))).ToList() ?? [];
    }

    public Task<bool> HasTvShowChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default) =>
        HasChangedSinceAsync("tv", tmdbId, since, cancellationToken);

    public Task<bool> HasMovieChangedSinceAsync(string tmdbId, DateTime since, CancellationToken cancellationToken = default) =>
        HasChangedSinceAsync("movie", tmdbId, since, cancellationToken);

    /// <summary>
    /// TMDB's per-id "changes" endpoint (as opposed to the bulk <c>/tv/changes</c>, <c>/movie/changes</c>
    /// endpoints which only cover the last 24-72h) reports whether anything changed since an arbitrary date -
    /// one cheap call instead of blindly re-fetching details plus every season for a show that hasn't moved.
    /// </summary>
    private async Task<bool> HasChangedSinceAsync(string resourceType, string tmdbId, DateTime since, CancellationToken cancellationToken)
    {
        var startDate = since.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var response = await http.GetFromJsonAsync<TmdbChangesResponse>(
            $"{resourceType}/{tmdbId}/changes?api_key={ApiKey}&start_date={startDate}", cancellationToken);
        return response?.Changes.Count > 0;
    }

    private string ApiKey => settings.ApiKey;

    private const string PosterImageSize = "w500";
    private const string ProfileImageSize = "w185";

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    private static int? ParseYear(string? date) => ParseDate(date)?.Year;

    private static DateOnly? ParseDate(string? date) =>
        !string.IsNullOrEmpty(date) && DateOnly.TryParse(date, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    /// <summary>
    /// TMDB's image CDN is a separate, unauthenticated static-asset host explicitly meant for direct
    /// hotlinking (not the rate-limited API) - the standard pattern every TMDB-consuming app uses, so
    /// this just builds the URL rather than downloading anything.
    /// </summary>
    private static string? BuildImageUrl(string? path, string size) =>
        string.IsNullOrEmpty(path) ? null : $"https://image.tmdb.org/t/p/{size}{path}";

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

        [JsonPropertyName("poster_path")]
        public string? PosterPath { get; set; }
    }

    private sealed class TmdbTvShowDetailsResponse
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("overview")]
        public string? Overview { get; set; }

        [JsonPropertyName("first_air_date")]
        public string? FirstAirDate { get; set; }

        [JsonPropertyName("poster_path")]
        public string? PosterPath { get; set; }

        [JsonPropertyName("genres")]
        public List<TmdbGenre> Genres { get; set; } = [];

        [JsonPropertyName("seasons")]
        public List<TmdbSeasonSummary> Seasons { get; set; } = [];
    }

    private sealed class TmdbGenre
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;
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

        [JsonPropertyName("poster_path")]
        public string? PosterPath { get; set; }

        [JsonPropertyName("genres")]
        public List<TmdbGenre> Genres { get; set; } = [];
    }

    private sealed class TmdbCreditsResponse
    {
        [JsonPropertyName("cast")]
        public List<TmdbCastMemberWire> Cast { get; set; } = [];
    }

    private sealed class TmdbChangesResponse
    {
        [JsonPropertyName("changes")]
        public List<object> Changes { get; set; } = [];
    }

    private sealed class TmdbCastMemberWire
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("character")]
        public string? Character { get; set; }

        [JsonPropertyName("order")]
        public int Order { get; set; }

        [JsonPropertyName("profile_path")]
        public string? ProfilePath { get; set; }
    }
}
