using System.Globalization;
using System.Text.Json.Serialization;
using System.Web;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// TMDB v3 client, a typed <see cref="HttpClient"/> with the API key as a query parameter, as TMDB's v3 authentication expects.
/// </summary>
public class TmdbClient(HttpClient http, TmdbSettings settings) : ITmdbClient
{
    /// <summary>
    /// <c>first_air_date_year</c> is a <b>hard</b> filter, so the search runs with and without the year and unions the answers, as an optional narrowing must never hide what a broader search finds.
    /// <para>
    /// <c>Severance</c> + 2021, <c>Squid Game</c> + 2020, <c>The Wire</c> + 2003 and <c>Adolescence</c> + 2024 each return <b>zero</b> results.
    /// A show whose first-air year is one off would be absent rather than ranked lower, and a wrong year must cost a place, never the result.
    /// </para>
    /// <para>
    /// The year still counts: <see cref="ReferenceMatchRules.OrderByBestMatch"/> ranks the requested year first, and confirmation requires it.
    /// The filtered query also keeps reachable a show that TMDB's relevance buries beyond the unfiltered first twenty.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var narrowed = year is null ? [] : await SearchTvShowCoreAsync(title, year, cancellationToken);
        var widened = await SearchTvShowCoreAsync(title, null, cancellationToken);
        return ReferenceMatchRules.OrderByBestMatch(Union(narrowed, widened), title, year).ToList();
    }

    private async Task<IReadOnlyList<TmdbSearchResult>> SearchTvShowCoreAsync(string title, int? year, CancellationToken cancellationToken)
    {
        var query = $"search/tv?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&first_air_date_year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? title, ParseYear(r.FirstAirDate), r.Overview, BuildImageUrl(r.PosterPath, PosterImageSize))).ToList() ?? [];
    }

    /// <summary>
    /// Unlike TV, the movie <c>year</c> is <b>not</b> a hard filter: <c>Road House</c> + 2024 still returns the 1989 film, and <c>Dune</c> + 2020 the 1984 one.
    /// It narrows without excluding, so one call is enough.
    /// <para>
    /// The results are still ranked: TMDB's search is fuzzy (<c>Heat</c> + 1995 returns fourteen), and its relevance can be wrong, <c>Sinners</c> + 2024 putting "In the Land of Saints and Sinners" first.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<TmdbSearchResult>> SearchMovieAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        var query = $"search/movie?api_key={ApiKey}&query={Encode(title)}" + (year is null ? "" : $"&year={year}");
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>(query, cancellationToken);
        var results = response?.Results.Select(r => new TmdbSearchResult(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Title ?? title, ParseYear(r.ReleaseDate), r.Overview, BuildImageUrl(r.PosterPath, PosterImageSize))).ToList() ?? [];
        return ReferenceMatchRules.OrderByBestMatch(results, title, year).ToList();
    }

    /// <summary>
    /// The narrower query's results first, then what the broader one adds, deduplicated by TMDB id since they overlap.
    /// </summary>
    private static List<TmdbSearchResult> Union(IReadOnlyList<TmdbSearchResult> narrowed, IReadOnlyList<TmdbSearchResult> widened)
    {
        var union = narrowed.ToList();
        union.AddRange(widened.Where(result => union.TrueForAll(known => known.TmdbId != result.TmdbId)));
        return union;
    }

    public async Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedMoviesAsync(int page, CancellationToken cancellationToken = default)
    {
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>($"movie/top_rated?api_key={ApiKey}&page={page}", cancellationToken);
        return response?.Results.Select(r => new TmdbTopRatedItem(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Title ?? string.Empty, ParseYear(r.ReleaseDate), r.Overview,
            BuildImageUrl(r.PosterPath, PosterImageSize), r.VoteAverage,
            ProviderWebLinks.TmdbMovie(r.Id.ToString(CultureInfo.InvariantCulture)))).ToList() ?? [];
    }

    public async Task<IReadOnlyList<TmdbTopRatedItem>> GetTopRatedTvShowsAsync(int page, CancellationToken cancellationToken = default)
    {
        var response = await http.GetFromJsonAsync<TmdbSearchResponse>($"tv/top_rated?api_key={ApiKey}&page={page}", cancellationToken);
        return response?.Results.Select(r => new TmdbTopRatedItem(
            r.Id.ToString(CultureInfo.InvariantCulture), r.Name ?? string.Empty, ParseYear(r.FirstAirDate), r.Overview,
            BuildImageUrl(r.PosterPath, PosterImageSize), r.VoteAverage,
            ProviderWebLinks.TmdbTvShow(r.Id.ToString(CultureInfo.InvariantCulture)))).ToList() ?? [];
    }

    public async Task<TmdbTvShowDetails?> GetTvShowDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
    {
        // append_to_response=external_ids brings the IMDb id, absent from /tv/{id} unlike a movie's, in the same call
        var details = await http.GetFromJsonAsync<TmdbTvShowDetailsResponse>(
            $"tv/{tmdbId}?api_key={ApiKey}&append_to_response=external_ids", cancellationToken);
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
            details.Genres.Select(g => g.Name).ToList(), BuildImageUrl(details.PosterPath, PosterImageSize),
            details.VoteAverage, details.VoteCount, details.ExternalIds?.ImdbId);
    }

    public async Task<TmdbMovieDetails?> GetMovieDetailsAsync(string tmdbId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<TmdbMovieDetailsResponse>($"movie/{tmdbId}?api_key={ApiKey}", cancellationToken);
        return details is null
            ? null
            : new TmdbMovieDetails(
                tmdbId, details.Title ?? string.Empty, ParseYear(details.ReleaseDate), details.Overview,
                details.Genres.Select(g => g.Name).ToList(), BuildImageUrl(details.PosterPath, PosterImageSize),
                details.VoteAverage, details.VoteCount, details.ImdbId);
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

    public Task<string?> GetTvShowImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default) =>
        GetImdbIdAsync($"tv/{tmdbId}/external_ids", cancellationToken);

    public Task<string?> GetMovieImdbIdAsync(string tmdbId, CancellationToken cancellationToken = default) =>
        GetImdbIdAsync($"movie/{tmdbId}/external_ids", cancellationToken);

    private async Task<string?> GetImdbIdAsync(string path, CancellationToken cancellationToken)
    {
        var response = await http.GetFromJsonAsync<TmdbExternalIds>($"{path}?api_key={ApiKey}", cancellationToken);
        return response?.ImdbId;
    }

    /// <summary>
    /// TMDB's "changes" endpoint per id, unlike the bulk ones limited to the last days, reports changes since any date, one cheap call rather than fetching the details and every season again.
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
    /// TMDB's image CDN is an unauthenticated host meant for hotlinking, so this only builds the URL.
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

        [JsonPropertyName("vote_average")]
        public double? VoteAverage { get; set; }
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

        [JsonPropertyName("vote_average")]
        public double? VoteAverage { get; set; }

        [JsonPropertyName("vote_count")]
        public int? VoteCount { get; set; }

        [JsonPropertyName("seasons")]
        public List<TmdbSeasonSummary> Seasons { get; set; } = [];

        [JsonPropertyName("external_ids")]
        public TmdbExternalIds? ExternalIds { get; set; }
    }

    private sealed class TmdbExternalIds
    {
        [JsonPropertyName("imdb_id")]
        public string? ImdbId { get; set; }
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

        [JsonPropertyName("vote_average")]
        public double? VoteAverage { get; set; }

        [JsonPropertyName("vote_count")]
        public int? VoteCount { get; set; }

        [JsonPropertyName("imdb_id")]
        public string? ImdbId { get; set; }
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
