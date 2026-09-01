using System.Text.Json.Serialization;
using System.Web;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Discogs REST client. Configured as a typed <see cref="HttpClient"/> with a descriptive User-Agent
/// header (required by Discogs' API terms) - see Program.cs. The personal access token is appended as a
/// query parameter on every request, same convention as <see cref="TmdbClient"/>/<see cref="RawgClient"/>.
/// Search is restricted to <c>type=master</c> so results resolve to a canonical release grouping rather
/// than every individual pressing/reissue.
/// </summary>
public class DiscogsClient(HttpClient http, DiscogsSettings settings) : IDiscogsClient
{
    public async Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsAsync(string title, int? year, string? artist = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchWithoutZeroingOutTheYearAsync(title, year, artist, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(artist))
        {
            // "no result" here also covers "the provider answered, but nothing it returned is actually
            // titled what was searched for" - SearchAlbumsCoreAsync discards those, and for the purpose of
            // deciding whether to widen the query they are the same thing as an empty response.
            // Discogs' artist field must match its own index closely (exact spelling, formatting, or a
            // disambiguation suffix like "Artist (2)" for a common name) - a mismatch there silently
            // returns zero results even when the title alone would find the album (confirmed: searching
            // "Born Pink" with an artist value that doesn't match Discogs' exact indexing returns nothing,
            // while the same title alone finds it), so retry without it rather than reporting a false
            // "not found".
            results = await SearchWithoutZeroingOutTheYearAsync(title, year, null, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// The same search asked with and without <c>year</c>, unioned - because Discogs' year <b>is</b> a hard
    /// filter, which this file previously recorded the opposite of ("no equivalent bug has been found for
    /// it").
    /// <para>
    /// Measured against the live API: <c>q=Kid A&amp;artist=Radiohead&amp;year=2001</c> returns exactly one
    /// master and it is <i>Amnesiac</i>, while the same query without the year finds the album immediately. An
    /// album's year is the least reliable thing a tenant records about it - a reissue, a pressing, the year
    /// they bought it - so a one-year disagreement must cost a place in the ranking, never the result.
    /// </para>
    /// <para>
    /// Nothing is loosened by this: the year still ranks candidates through
    /// <see cref="ReferenceMatchRules.OrderByBestMatch"/>, and the artist re-check above and the title
    /// re-check in <see cref="SearchAlbumsCoreAsync"/> both still apply to everything the wider query adds.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<DiscogsSearchResult>> SearchWithoutZeroingOutTheYearAsync(
        string title, int? year, string? artist, CancellationToken cancellationToken)
    {
        var narrowed = year is null ? [] : await SearchAlbumsCoreAsync(title, year, artist, cancellationToken);
        var widened = await SearchAlbumsCoreAsync(title, null, artist, cancellationToken);

        var union = narrowed.ToList();
        union.AddRange(widened.Where(result => union.TrueForAll(known => known.ExternalId != result.ExternalId)));
        return ReferenceMatchRules.OrderByBestMatch(union, title, year).ToList();
    }

    /// <summary>
    /// <c>q=</c> is Discogs' free-text parameter, not a title field: it matches the artist name, the label,
    /// credits and the tracklist too, so results whose release title has nothing to do with the searched
    /// title come back as ordinary hits. Confirmed against the real API - <c>q=Discovery&amp;artist=Daft Punk</c>
    /// returns "Live @ Rex Club, Paris" and "MP3 Collection" beside the album, and <c>q=Sabbath</c> returns
    /// releases whose only occurrence of the word is "Black Sabbath" in the artist name.
    /// <para>
    /// Every candidate's own release title is therefore re-checked here (<see cref="TitleNormalizer.LooselyContains"/>)
    /// and mismatches discarded, the same client-side re-check <c>BnfClient.AuthorMatches</c> applies to a
    /// provider clause that isn't a strict filter either. The check runs on the *parsed* album title from
    /// <see cref="SplitArtistTitle"/>, which is what excludes a match that only ever occurred in the artist
    /// half of Discogs' combined "Artist - Title" string.
    /// </para>
    /// <para>
    /// Switching to Discogs' field-scoped <c>release_title=</c> instead was measured and rejected: it is
    /// precise (2350 hits down to 209 for "Sabbath", all genuine title matches) but reorders results badly -
    /// <c>release_title=Nevermind&amp;artist=Nirvana</c> ranks the canonical 1991 album fourth, behind
    /// "Nevermind Sessions" - and callers only ever look at the first few candidates
    /// (<c>ReferenceDataAdminController.MaxEnrichedCandidates</c>). Filtering keeps <c>q=</c>'s relevance
    /// order and removes only what doesn't belong.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsCoreAsync(string title, int? year, string? artist, CancellationToken cancellationToken)
    {
        var query = $"database/search?type=master&q={Encode(title)}&token={Token}"
                    + (year is null ? "" : $"&year={year}")
                    + (string.IsNullOrEmpty(artist) ? "" : $"&artist={Encode(artist)}");
        var response = await http.GetFromJsonAsync<DiscogsSearchResponse>(query, cancellationToken);
        return response?.Results.Select(r =>
        {
            var (artist, albumTitle) = SplitArtistTitle(r.Title, title);
            return new DiscogsSearchResult(r.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), albumTitle, r.Year, artist, r.CoverImage ?? r.Thumb);
        })
        .Where(r => TitleNormalizer.LooselyContains(r.Title, title))
        .ToList() ?? [];
    }

    public async Task<DiscogsAlbumDetails?> GetAlbumDetailsAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var details = await http.GetFromJsonAsync<DiscogsMasterResponse>($"masters/{externalId}?token={Token}", cancellationToken);
        if (details is null) return null;

        var genres = details.Genres.Concat(details.Styles).ToList();
        var image = details.Images.FirstOrDefault()?.Uri;
        var primaryArtist = details.Artists.FirstOrDefault();
        var tracks = details.Tracklist
            .Where(t => t.Type == "track")
            .Select(t => new DiscogsTrack(t.Position ?? "", t.Title ?? "", t.Duration))
            .ToList();

        // A Discogs community rating lives on an individual *release*, not the master grouping we search/fetch,
        // so fetch the master's canonical main_release to read it. Best-effort: a missing release or rating
        // just leaves the album without a reference rating rather than failing the whole resolve.
        var (rating, ratingCount) = await GetCommunityRatingAsync(details.MainRelease, cancellationToken);

        return new DiscogsAlbumDetails(
            externalId, details.Title ?? string.Empty, details.Year, details.Notes,
            primaryArtist?.Name, primaryArtist?.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), genres, image, tracks,
            rating, ratingCount);
    }

    private async Task<(double? Rating, int? Count)> GetCommunityRatingAsync(int? mainReleaseId, CancellationToken cancellationToken)
    {
        if (mainReleaseId is null or 0) return (null, null);
        var release = await http.GetFromJsonAsync<DiscogsReleaseResponse>($"releases/{mainReleaseId}?token={Token}", cancellationToken);
        var rating = release?.Community?.Rating;
        // Discogs reports average 0 / count 0 for an unrated release - treat that as "no rating", not a real 0.
        return rating is { Average: > 0, Count: > 0 } ? (rating.Average, rating.Count) : (null, null);
    }

    private string Token => settings.Token;

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    /// <summary>
    /// Discogs' search results title a release "Artist - Album Title" rather than exposing the two as
    /// separate fields - split on the first " - " when present, falling back to the tenant's own search
    /// title if the shape doesn't match (e.g. an artist name that itself contains " - ").
    /// </summary>
    private static (string? Artist, string Title) SplitArtistTitle(string? rawTitle, string fallbackTitle)
    {
        if (string.IsNullOrEmpty(rawTitle)) return (null, fallbackTitle);
        var separatorIndex = rawTitle.IndexOf(" - ", System.StringComparison.Ordinal);
        return separatorIndex < 0 ? (null, rawTitle) : (rawTitle[..separatorIndex], rawTitle[(separatorIndex + 3)..]);
    }

    private sealed class DiscogsSearchResponse
    {
        [JsonPropertyName("results")]
        public List<DiscogsSearchItem> Results { get; set; } = [];
    }

    private sealed class DiscogsSearchItem
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("year")]
        public int? Year { get; set; }

        [JsonPropertyName("thumb")]
        public string? Thumb { get; set; }

        [JsonPropertyName("cover_image")]
        public string? CoverImage { get; set; }
    }

    private sealed class DiscogsMasterResponse
    {
        [JsonPropertyName("main_release")]
        public int? MainRelease { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("year")]
        public int? Year { get; set; }

        [JsonPropertyName("notes")]
        public string? Notes { get; set; }

        [JsonPropertyName("genres")]
        public List<string> Genres { get; set; } = [];

        [JsonPropertyName("styles")]
        public List<string> Styles { get; set; } = [];

        [JsonPropertyName("images")]
        public List<DiscogsImage> Images { get; set; } = [];

        [JsonPropertyName("artists")]
        public List<DiscogsArtist> Artists { get; set; } = [];

        [JsonPropertyName("tracklist")]
        public List<DiscogsTracklistItem> Tracklist { get; set; } = [];
    }

    /// <summary>
    /// <c>type_</c> distinguishes an actual track from a section heading some multi-part releases use
    /// (e.g. "index") - only entries with <c>type_ == "track"</c> are real songs.
    /// </summary>
    private sealed class DiscogsTracklistItem
    {
        [JsonPropertyName("position")]
        public string? Position { get; set; }

        [JsonPropertyName("type_")]
        public string? Type { get; set; }

        [JsonPropertyName("title")]
        public string? Title { get; set; }

        [JsonPropertyName("duration")]
        public string? Duration { get; set; }
    }

    private sealed class DiscogsImage
    {
        [JsonPropertyName("uri")]
        public string? Uri { get; set; }
    }

    /// <summary>The individual-release resource (fetched via a master's <c>main_release</c>) - the only place Discogs exposes a community rating.</summary>
    private sealed class DiscogsReleaseResponse
    {
        [JsonPropertyName("community")]
        public DiscogsCommunity? Community { get; set; }
    }

    private sealed class DiscogsCommunity
    {
        [JsonPropertyName("rating")]
        public DiscogsRating? Rating { get; set; }
    }

    private sealed class DiscogsRating
    {
        [JsonPropertyName("average")]
        public double Average { get; set; }

        [JsonPropertyName("count")]
        public int Count { get; set; }
    }

    private sealed class DiscogsArtist
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}
