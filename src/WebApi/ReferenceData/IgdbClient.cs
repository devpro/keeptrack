using System.Globalization;
using System.Text;
using System.Text.Json.Serialization;
using Keeptrack.Domain.Models;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// IGDB (Internet Game Database, part of Twitch) client - the default video game reference provider, replacing
/// <see cref="RawgClient"/>.
/// <para>
/// Two things make it unlike every other provider client here, both handled outside this class so it stays a
/// plain typed <see cref="HttpClient"/>: authentication is a Twitch app access token rather than an api key
/// (<see cref="IgdbAuthenticationHandler"/>), and the API documents a 4 requests/second ceiling
/// (<see cref="IgdbRateLimitHandler"/>). What is visible here is the third difference: queries are POST bodies
/// written in IGDB's own Apicalypse language, not query-string parameters.
/// </para>
/// <para>
/// Every call short-circuits to an empty result when no credentials are configured, so a deployment that has
/// not set <c>Igdb:ClientId</c>/<c>Igdb:ClientSecret</c> degrades to "no video game reference data" rather
/// than failing every request - see <see cref="IgdbSettings"/>.
/// </para>
/// </summary>
public class IgdbClient(HttpClient http, IgdbSettings settings) : IVideoGameReferenceClient
{
    public string ProviderKey => RatingSourceCatalog.Igdb;

    public string DisplayName => "IGDB";

    /// <summary>
    /// IGDB's own 0-100 user score (its default ordering) and its 0-100 aggregate of external critic scores.
    /// Metacritic is deliberately absent: IGDB does not report it, and its critic aggregate is computed from
    /// IGDB's own sources, so writing it under Metacritic's key would misattribute the number.
    /// </summary>
    public IReadOnlyList<string> SupportedRatingSources { get; } = [RatingSourceCatalog.Igdb, RatingSourceCatalog.IgdbCritic];

    public async Task<IReadOnlyList<VideoGameSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured || string.IsNullOrWhiteSpace(title)) return [];

        // no year filter, deliberately: Apicalypse rejects `sort` alongside `search`, and narrowing a relevance
        // search by an exact release year is the same trap OpenLibraryClient documents - an edition/regional
        // release routinely carries a different year from the one a tenant typed, and filtering it away turns a
        // good match into no match at all. The year is returned per candidate for the caller to tie-break with.
        var query = $"{SearchFields} search \"{EscapeSearchTerm(title)}\"; limit {MaxResults};";
        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameSearchResult(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? title, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover))).ToList();
    }

    public async Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured || string.IsNullOrWhiteSpace(title)) return [];

        // `name ~ "..."` is Apicalypse's case-insensitive *equality* on a string field, not the relevance
        // `search` above - confirmed live: it returns the seven distinct games IGDB names exactly "Resident
        // Evil" (1996 original, 2002 remake, ports, the 2014 HD remaster), where `search "Resident Evil"`
        // returned only bundles and archive editions. A larger limit than the search path because this is a
        // complete answer to a narrow question: truncating it would turn "several candidates, don't guess"
        // into "exactly one, adopt it" purely by cutting the list short.
        var query = $"{SearchFields} where name ~ \"{EscapeSearchTerm(title)}\"; limit {MaxExactTitleResults};";
        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameSearchResult(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? title, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover))).ToList();
    }

    public async Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        // ids are IGDB's own numeric ids; anything else is not a value this provider issued, and interpolating
        // it into an Apicalypse `where` would be an injection point
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

    public async Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured) return [];

        var critic = ratingSource == RatingSourceCatalog.IgdbCritic;
        var (sortField, countField, minCount) = critic
            ? ("aggregated_rating", "aggregated_rating_count", MinCriticRatingCount)
            : ("rating", "rating_count", MinUserRatingCount);

        // the vote-count floor is the whole reason this ranking is trustworthy, and it is a genuine improvement
        // on what RAWG allowed: RAWG exposed no vote count at all, so RawgClient had to approximate "enough
        // people have judged this" with "Metacritic reviewed it". Ordering by a plain average without a floor
        // ranks a single-vote unknown above every classic.
        //
        // It is deliberately the *only* filter. IGDB can restrict this to parent titles with `game_type = 0`,
        // and an earlier version did, but a DLC or a remaster is a first-class thing to track here (owner's
        // call): "Shadow of the Erdtree" and "The Last of Us Remastered" are records someone genuinely wants,
        // so a well-reviewed expansion is a legitimate suggestion rather than noise beside its own parent.
        var query = $"{TopRatedFields} where {countField} >= {minCount}; " +
                    $"sort {sortField} desc; limit {TopRatedPageSize}; offset {Math.Max(page - 1, 0) * TopRatedPageSize};";

        var games = await QueryAsync(query, cancellationToken);
        return games.Select(g => new VideoGameTopRatedItem(
            g.Id.ToString(CultureInfo.InvariantCulture), g.Name ?? string.Empty, ParseYear(g.FirstReleaseDate), CoverUrl(g.Cover),
            BuildRatings(g).ToDictionary(r => r.Key, r => r.Value.Value), g.Url)).ToList();
    }

    // the admin's candidate list renders a small portrait thumb, so a search hit stays on the box art.
    private const string SearchFields = "fields name,first_release_date,cover.image_id;";

    private const string DetailFields =
        "fields name,summary,first_release_date,genres.name,platforms.name,cover.image_id," +
        "rating,rating_count,aggregated_rating,aggregated_rating_count;";

    // cover only, like every other query here, plus `url`: a discovery card links out to the game's IGDB page
    // so a suggestion can be read up on before it is added or dismissed, and that page is keyed on a slug the
    // numeric id can't be turned into.
    private const string TopRatedFields =
        "fields name,first_release_date,cover.image_id,rating,rating_count,aggregated_rating,aggregated_rating_count,url;";

    private const int MaxResults = 5;

    /// <summary>
    /// Bound on <see cref="FindGamesByExactTitleAsync"/>. Higher than <see cref="MaxResults"/> on purpose: an
    /// exact-name query returns only genuine namesakes, and seeing all of them is what makes "more than one -
    /// leave it for an admin" a real judgement (a common name like "Resident Evil" has seven).
    /// </summary>
    private const int MaxExactTitleResults = 50;

    /// <summary>IGDB's per-query maximum, so a full catalogue ranking costs as few round-trips as possible.</summary>
    private const int TopRatedPageSize = 500;

    /// <summary>
    /// Notability floor for the user-score ranking. IGDB reports a vote count per game, so unlike RAWG this can
    /// be an actual minimum rather than a proxy. Raise it for a stricter list.
    /// </summary>
    private const int MinUserRatingCount = 200;

    /// <summary>
    /// Notability floor for the critic ranking. Much lower than the user one on purpose - a game reviewed by a
    /// handful of outlets has still been judged by the press, and critic counts are an order of magnitude
    /// smaller than user counts (confirmed live: the top of this ranking carries counts of 8 to 27, against
    /// thousands of user ratings for the same titles).
    /// </summary>
    private const int MinCriticRatingCount = 5;

    /// <summary>
    /// IGDB serves cover art from its own CDN, hotlinked exactly like TMDB's - the size token is part of the
    /// path and the id identifies the image.
    /// <para>
    /// <c>t_1080p</c> is the largest token IGDB offers, and for a cover it yields 810x1080 - every token keeps
    /// the source's own 3:4 aspect (IGDB scales to fit rather than letterboxing), so this is purely resolution.
    /// Measured on the live CDN against a real cover id: <c>t_cover_big</c> 264x352, <c>t_cover_big_2x</c>
    /// 528x704, <c>t_720p</c> 540x720, <c>t_1080p</c> 810x1080 (~107 KB). Box art is detailed artwork shown
    /// large on the detail page, so it takes the biggest available rather than the smallest that "should" do.
    /// </para>
    /// <para>
    /// The cover is the only image used. IGDB's landscape collections were both tried and are worse: artwork is
    /// contributed rather than curated (RDR2's first is posterised fan art at 720x720, Baldur's Gate III's is a
    /// bare logo on black), and screenshots are raw in-game frames with HUD in them. Neither is the curated key
    /// art RAWG's <c>background_image</c> was, and IGDB has no equivalent of it.
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
    /// IGDB's two aggregates as a <c>Ratings</c> map, both on a 0-100 scale. A 0/absent value is treated as "no
    /// rating" and omitted, never stored as a genuine zero.
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
    /// Makes a tenant-typed title safe to embed in an Apicalypse string literal. Quotes and backslashes are
    /// escaped and control characters dropped: a raw <c>"</c> or <c>;</c> in a title would otherwise end the
    /// literal and let the rest of the title be parsed as query syntax.
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

        /// <summary>The game's own page on igdb.com. Requested rather than built: it is keyed on a slug, not on <see cref="Id"/>.</summary>
        [JsonPropertyName("url")]
        public string? Url { get; set; }
    }

    /// <summary>An IGDB image is just an <c>image_id</c> on its own record.</summary>
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
