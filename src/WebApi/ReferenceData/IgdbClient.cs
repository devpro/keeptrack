using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// IGDB (Internet Game Database, part of Twitch) client, the default video game provider.
/// <para>
/// It differs from the other clients in three ways.
/// Two are handled around it, so it stays a plain typed <see cref="HttpClient"/>: a Twitch app token rather than an API key (<see cref="IgdbAuthenticationHandler"/>), and a 4 requests per second ceiling (<see cref="IgdbRateLimitHandler"/>).
/// The third shows here: queries are POST bodies in IGDB's Apicalypse language.
/// </para>
/// <para>
/// Without credentials every call returns an empty result rather than failing (see <see cref="IgdbSettings"/>).
/// </para>
/// </summary>
public class IgdbClient(HttpClient http, IgdbSettings settings) : VideoGameReferenceClientBase
{
    public override string ProviderKey => RatingSourceCatalog.Igdb;

    public override string DisplayName => "IGDB";

    /// <summary>
    /// IGDB's 0 to 100 user score, its default ordering, and its 0 to 100 aggregate of critic scores.
    /// Not Metacritic, which IGDB does not report, its critic aggregate coming from its own sources.
    /// </summary>
    public override IReadOnlyList<string> SupportedRatingSources { get; } = [RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic];

    protected override async Task<IReadOnlyList<VideoGameSearchResult>> SearchByRelevanceAsync(string title, int limit, CancellationToken cancellationToken)
    {
        if (!settings.IsConfigured) return [];

        // no `where first_release_date`, the year ranking the pool rather than filtering it (see VideoGameReferenceClientBase.SearchByRelevanceAsync)
        var query = $"{SearchFields} search \"{EscapeSearchTerm(title)}\"; limit {limit};";
        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameSearchResult(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? title, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover))).ToList();
    }

    public override async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured || string.IsNullOrWhiteSpace(title)) return [];

        // `name ~ "..."` is Apicalypse's case-insensitive equality, not the relevance `search`: it returns the seven games named exactly "Resident Evil", where `search` returns bundles.
        // A larger limit than search, since truncating this complete answer could turn "several candidates" into "exactly one".
        var query = $"{SearchFields} where name ~ \"{EscapeSearchTerm(title)}\"; limit {MaxExactTitleResults};";
        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameSearchResult(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? title, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover))).ToList();
    }

    public override async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured || words.Count == 0) return [];

        // `name ~ *"..."*` is Apicalypse's case-insensitive contains, and joining several survives punctuation the reference lacks: each word is a substring of "Marvel's Avengers", where the phrase matches nothing
        var filter = string.Join(" & ", words.Select(word => $"name ~ *\"{EscapeSearchTerm(word)}\"*"));
        var games = await QueryAsync($"{SearchFields} where {filter}; limit {MaxContainsResults};", cancellationToken);
        return games.Select(g => new VideoGameSearchResult(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? string.Empty, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover))).ToList();
    }

    public override async Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured || string.IsNullOrWhiteSpace(identifier)) return null;

        // IGDB keys pages on `slug`, a filterable field, so a copied address resolves in one call: `where slug = "marvels-avengers"` finds the game no spelling of its name does
        var filter = long.TryParse(identifier, NumberStyles.None, CultureInfo.InvariantCulture, out var id)
            ? $"id = {id}"
            : $"slug = \"{EscapeSearchTerm(identifier)}\"";

        var games = await QueryAsync($"{SearchFields} where {filter}; limit 1;", cancellationToken);
        return games.Count == 0
            ? null
            : new VideoGameSearchResult(
                games[0].Id.ToString(CultureInfo.InvariantCulture), games[0].Name ?? identifier,
                ParseYear(games[0].FirstReleaseDate), CoverUrl(games[0].Cover));
    }

    public override async Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        // only IGDB's numeric ids are accepted, since anything else interpolated into an Apicalypse `where` would be an injection point
        if (!settings.IsConfigured || !long.TryParse(externalId, NumberStyles.None, CultureInfo.InvariantCulture, out var id)) return null;

        var games = await QueryAsync($"{DetailFields} where id = {id};", cancellationToken);
        if (games.Count == 0) return null;

        var game = games[0];
        return new VideoGameDetails(
            externalId,
            game.Name ?? string.Empty,
            ParseYear(game.FirstReleaseDate),
            game.Summary,
            game.Genres.Select(g => g.Name).OfType<string>().ToList(),
            game.Platforms.Select(p => p.Name).OfType<string>().ToList(),
            CoverUrl(game.Cover),
            BuildRatings(game));
    }

    public override async Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured) return [];

        var critic = ratingSource == RatingSourceCatalog.IgdbCritic;
        var (sortField, countField, minCount) = critic
            ? ("aggregated_rating", "aggregated_rating_count", MinCriticRatingCount)
            : ("rating", "rating_count", MinUserRatingCount);

        // The vote-count floor makes the ranking trustworthy, since a plain average ranks a single-vote unknown above every classic.
        //
        // It is the only filter.
        // `game_type = 0` would keep parent titles only, but a DLC or remaster is worth tracking (owner's call): "Shadow of the Erdtree" and "The Last of Us Remastered" are legitimate suggestions.
        var query = $"{TopRatedFields} where {countField} >= {minCount}; " +
                    $"sort {sortField} desc; limit {TopRatedPageSize}; offset {Math.Max(page - 1, 0) * TopRatedPageSize};";

        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameTopRatedItem(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? string.Empty, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover),
            BuildRatings(g).ToDictionary(r => r.Key, r => r.Value.Value), g.Url)).ToList();
    }

    // the admin's candidate list shows a small portrait thumbnail, so a search hit keeps the box art
    private const string SearchFields = "fields name,first_release_date,cover.image_id;";

    private const string DetailFields =
        "fields name,summary,first_release_date,genres.name,platforms.name,cover.image_id," +
        "rating,rating_count,aggregated_rating,aggregated_rating_count;";

    // cover only, plus `url`, since a discovery card links to the game's IGDB page, keyed on a slug the id cannot be turned into
    private const string TopRatedFields =
        "fields name,first_release_date,cover.image_id,rating,rating_count,aggregated_rating,aggregated_rating_count,url;";

    /// <summary>
    /// Bound of <see cref="FindGamesByExactTitleAsync"/>, higher than a search displays: an exact query returns only namesakes, and seeing all of them makes "more than one, leave it to an admin" a real judgement ("Resident Evil" has seven).
    /// </summary>
    private const int MaxExactTitleResults = 50;

    /// <summary>
    /// Bound of <see cref="FindGamesContainingAllWordsAsync"/>, a cost ceiling rather than a window, since a substring filter has no ordering and the caller shortlists the result.
    /// "marvel" and "avengers" return 40 games, so this covers a real query while capping a careless one.
    /// </summary>
    private const int MaxContainsResults = 100;

    /// <summary>IGDB's maximum per query, so a whole ranking costs as few round trips as possible.</summary>
    private const int TopRatedPageSize = 500;

    /// <summary>
    /// Notability floor of the user-score ranking, a real minimum since IGDB reports a vote count per game.
    /// </summary>
    private const int MinUserRatingCount = 200;

    /// <summary>
    /// Notability floor of the critic ranking, much lower than the user one, since critic counts are about ten times smaller (8 to 27 at the top of the ranking, against thousands of user ratings).
    /// </summary>
    private const int MinCriticRatingCount = 5;

    /// <summary>
    /// IGDB serves covers from its CDN, hotlinked like TMDB's, the size token in the path and the id naming the image.
    /// <para>
    /// <c>t_1080p</c> is the largest token, 810x1080 for a cover, every token keeping the 3:4 shape, so it only picks a resolution.
    /// Box art is shown large on the detail page, so it takes the biggest available.
    /// </para>
    /// <para>
    /// The cover is the only image used.
    /// IGDB's artworks are contributed rather than curated (Red Dead Redemption 2's first is posterised fan art), and its screenshots are raw frames with the HUD, so neither replaces RAWG's curated key art.
    /// </para>
    /// </summary>
    private const string CoverUrlTemplate = "https://images.igdb.com/igdb/image/upload/t_1080p/{0}.jpg";

    private async Task<List<IgdbGame>> QueryAsync(string query, CancellationToken cancellationToken)
    {
        using var content = new StringContent(query, Encoding.UTF8, "text/plain");
        using var response = await http.PostAsync("games", content, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<List<IgdbGame>>(cancellationToken) ?? [];
    }

    /// <summary>
    /// IGDB's two aggregates as a <c>Ratings</c> map, both 0 to 100.
    /// A zero or absent value means no rating and is omitted, never stored as zero.
    /// </summary>
    private static Dictionary<string, ReferenceRatingModel> BuildRatings(IgdbGame game)
    {
        var ratings = new Dictionary<string, ReferenceRatingModel>();
        if (game.Rating is > 0)
        {
            ratings[RatingSourceCatalog.Igdb] = new ReferenceRatingModel { Value = game.Rating.Value, Scale = 100, Count = game.RatingCount };
        }
        if (game.AggregatedRating is > 0)
        {
            ratings[RatingSourceCatalog.IgdbCritic] = new ReferenceRatingModel { Value = game.AggregatedRating.Value, Scale = 100, Count = game.AggregatedRatingCount };
        }
        return ratings;
    }

    /// <summary>
    /// Makes a title a tenant typed safe inside an Apicalypse string literal.
    /// Quotes and backslashes are escaped and control characters dropped, since a raw <c>"</c> would end the literal and let the rest parse as query syntax.
    /// </summary>
    private static string EscapeSearchTerm(string title)
    {
        var escaped = new StringBuilder(title.Length);
        foreach (var character in title)
        {
            if (char.IsControl(character)) continue;
            if (character is '"' or '\\') escaped.Append('\\');
            escaped.Append(character);
        }

        return escaped.ToString();
    }

    private static int? ParseYear(long? firstReleaseDate) =>
        firstReleaseDate is null or <= 0 ? null : DateTimeOffset.FromUnixTimeSeconds(firstReleaseDate.Value).Year;

    private static string? CoverUrl(IgdbCover? cover) =>
        string.IsNullOrEmpty(cover?.ImageId) ? null : string.Format(CultureInfo.InvariantCulture, CoverUrlTemplate, cover.ImageId);

    private sealed class IgdbGame
    {
        [JsonPropertyName("id")]
        public long Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("summary")]
        public string? Summary { get; set; }

        [JsonPropertyName("first_release_date")]
        public long? FirstReleaseDate { get; set; }

        [JsonPropertyName("cover")]
        public IgdbCover? Cover { get; set; }

        [JsonPropertyName("genres")]
        public List<IgdbNamed> Genres { get; set; } = [];

        [JsonPropertyName("platforms")]
        public List<IgdbNamed> Platforms { get; set; } = [];

        [JsonPropertyName("rating")]
        public double? Rating { get; set; }

        [JsonPropertyName("rating_count")]
        public int? RatingCount { get; set; }

        [JsonPropertyName("aggregated_rating")]
        public double? AggregatedRating { get; set; }

        [JsonPropertyName("aggregated_rating_count")]
        public int? AggregatedRatingCount { get; set; }

        /// <summary>The game's page on igdb.com, requested rather than built, since it is keyed on a slug rather than <see cref="Id"/>.</summary>
        [JsonPropertyName("url")]
        public string? Url { get; set; }
    }

    /// <summary>An IGDB image is an <c>image_id</c> on its own record.</summary>
    private sealed class IgdbCover
    {
        [JsonPropertyName("image_id")]
        public string? ImageId { get; set; }
    }

    private sealed class IgdbNamed
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}
