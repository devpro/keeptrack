using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One Discogs master release search hit: title, year, artist and cover, enough for automatic matching or for an admin to pick from.
/// </summary>
public record DiscogsSearchResult(string ExternalId, string Title, int? Year, string? Artist, string? ImageUrl) : ICreatorSearchCandidate
{
    /// <summary>An album's identity is its title plus its artist (see <see cref="ReferenceMatchRules"/>).</summary>
    public string? Creator => Artist;
}

public record DiscogsAlbumDetails(string ExternalId, string Title, int? Year, string? Synopsis, string? Artist, string? ArtistExternalId, List<string> Genres, string? ImageUrl, List<DiscogsTrack> Tracks, double? Rating = null, int? RatingCount = null);

/// <summary>
/// One tracklist entry of Discogs' <c>/masters/{id}</c>: <paramref name="Position"/> is not always numeric (vinyl uses side and track, like "A1"), and <paramref name="Duration"/> is Discogs' "M:SS" text, often absent.
/// </summary>
public record DiscogsTrack(string Position, string Title, string? Duration);

/// <summary>
/// Thin wrapper over the Discogs REST API, an interface so tests use a fake.
/// Search is restricted to <c>type=master</c>, so results are the canonical release grouping rather than every pressing and reissue.
/// </summary>
public interface IDiscogsClient
{
    /// <summary>
    /// <paramref name="artist"/> narrows the query when known (Discogs' <c>artist</c> field), since a common title returns dozens of other artists' albums.
    /// </summary>
    Task<IReadOnlyList<DiscogsSearchResult>> SearchAlbumsAsync(string title, int? year, string? artist = null, CancellationToken cancellationToken = default);

    Task<DiscogsAlbumDetails?> GetAlbumDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
