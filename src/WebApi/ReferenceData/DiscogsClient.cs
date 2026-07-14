using System.Text.Json.Serialization;
using System.Web;

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
        var results = await SearchAlbumsCoreAsync(title, year, artist, cancellationToken);
        if (results.Count == 0 && !string.IsNullOrEmpty(artist))
        {
            // Discogs' artist field must match its own index closely (exact spelling, formatting, or a
            // disambiguation suffix like "Artist (2)" for a common name) - a mismatch there silently
            // returns zero results even when the title alone would find the album (confirmed: searching
            // "Born Pink" with an artist value that doesn't match Discogs' exact indexing returns nothing,
            // while the same title alone finds it), so retry without it rather than reporting a false
            // "not found". Year is kept, since no equivalent bug has been found for it (unlike Open
            // Library's book-year problem - see IOpenLibraryClient.SearchBooksAsync).
            results = await SearchAlbumsCoreAsync(title, year, null, cancellationToken);
        }

        return results;
    }

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
        }).ToList() ?? [];
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

        return new DiscogsAlbumDetails(
            externalId, details.Title ?? string.Empty, details.Year, details.Notes,
            primaryArtist?.Name, primaryArtist?.Id.ToString(System.Globalization.CultureInfo.InvariantCulture), genres, image, tracks);
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

    private sealed class DiscogsArtist
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }
    }
}
