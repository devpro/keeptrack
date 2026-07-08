using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One Discogs master-release search hit - title, year, artist and cover art, enough for automatic
/// matching or for an admin to pick from when a match is ambiguous.
/// </summary>
public record DiscogsSearchResult(string ExternalId, string Title, int? Year, string? Artist, string? ImageUrl);

public record DiscogsAlbumDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Artist, string? ArtistExternalId, List<string> Genres, string? ImageUrl, List<DiscogsTrack> Tracks);

/// <summary>
/// One tracklist entry from Discogs' <c>/masters/{id}</c> response - <paramref name="Position"/> isn't
/// always numeric (vinyl releases use side+track like "A1"/"B2"), and <paramref name="Duration"/> is
/// Discogs' own "M:SS" text, often absent.
/// </summary>
public record DiscogsTrack(string Position, string Title, string? Duration);

/// <summary>
/// Thin wrapper over the Discogs REST API. Interface exists so tests use a fake - never call the real
/// Discogs API from a test. Search is restricted to <c>type=master</c> so results resolve to a canonical
/// release grouping rather than every individual pressing/reissue.
/// </summary>
public interface IDiscogsClient
{
    /// <summary>
    /// <paramref name="artist"/> narrows the query when known (Discogs' own <c>artist</c> search field) -
    /// without it, a common album title can return dozens of unrelated results from other artists.
    /// </summary>
    Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsAsync(string title, int? year, string? artist = null, CancellationToken cancellationToken = default);

    Task<DiscogsAlbumDetails?> GetAlbumDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
