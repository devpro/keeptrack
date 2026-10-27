using System.Text.Json.Serialization;
using System.Web;
using Keeptrack.Common.System;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Discogs client, a typed <see cref="HttpClient"/> with the descriptive User-Agent Discogs' terms require, and the personal access token as a query parameter.
/// Search is restricted to <c>type=master</c>, the canonical grouping rather than every pressing and reissue.
/// </summary>
public class DiscogsClient(HttpClient http, DiscogsSettings settings) : IDiscogsClient
{
    public async Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsAsync(string title, int? year, string? artist = null, CancellationToken cancellationToken = default)
    {
        var results = await SearchWithoutZeroingOutTheYearAsync(title, year, artist, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(artist))
        {
            // No result includes nothing titled as searched, which SearchAlbumsCoreAsync discards.
            // Discogs' artist must match its index closely (spelling, a suffix like "Artist (2)"),
            // and a mismatch returns nothing although the title alone finds the album, so the search retries without it.
            results = await SearchWithoutZeroingOutTheYearAsync(title, year, null, cancellationToken);
        }

        return results;
    }

    /// <summary>
    /// The search asked with and without <c>year</c>, unioned, since Discogs' year <b>is</b> a hard filter.
    /// <para>
    /// <c>q=Kid A&amp;artist=Radiohead&amp;year=2001</c> returns one master, <i>Amnesiac</i>, while the query without the year finds the album.
    /// An album's year is the least reliable thing a tenant records (a reissue, a pressing, the purchase year), so a year off must cost a place, never the result.
    /// </para>
    /// <para>
    /// Nothing loosens: the year still ranks through <see cref="ReferenceMatchRules.OrderByBestMatch"/>, and the artist and title checks apply to everything the wider query adds.
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
    /// <c>q=</c> is Discogs' free-text parameter, not a title field: it also matches the artist, label, credits and tracklist, so unrelated releases come back as hits.
    /// <c>q=Discovery&amp;artist=Daft Punk</c> returns "Live @ Rex Club, Paris" beside the album, and <c>q=Sabbath</c> releases naming the word only in "Black Sabbath".
    /// <para>
    /// Every candidate's release title is therefore checked (<see cref="TitleNormalizer.LooselyContains"/>) and mismatches discarded,
    /// as <c>BnfClient.AuthorMatches</c> does for authors.
    /// The check reads the album half parsed by <see cref="SplitArtistTitle"/>, so a word found only in the artist half does not count.
    /// </para>
    /// <para>
    /// <c>release_title=</c> is precise but ranks badly, putting the 1991 <c>Nevermind</c> fourth behind "Nevermind Sessions", while callers look only at the first few candidates.
    /// Filtering keeps <c>q=</c>'s relevance order and removes only what does not belong.
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

        // A community rating lives on a release, not on the master searched here, so the master's main_release is fetched for it.
        // Best effort: a missing release or rating leaves the album unrated rather than failing the resolve.
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
        // an unrated release reports average 0 and count 0, which means no rating
        return rating is { Average: > 0, Count: > 0 } ? (rating.Average, rating.Count) : (null, null);
    }

    private string Token => settings.Token;

    private static string Encode(string value) => HttpUtility.UrlEncode(value);

    /// <summary>
    /// Discogs titles a search result "Artist - Album Title" rather than separating them,
    /// so it is split on the first " - ", falling back to the searched title when the shape differs.
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
    /// <c>type_</c> tells a track from a section heading of a multi-part release ("index"), only <c>type_ == "track"</c> being a song.
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

    /// <summary>A release, fetched through a master's <c>main_release</c>, the only place Discogs exposes a community rating.</summary>
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
