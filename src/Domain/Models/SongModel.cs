using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class SongModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public string? Artist { get; set; }

    /// <summary>
    /// Optional link to the tenant's own album, a soft reference like <c>ReferenceId</c>: nothing enforces or cascades it when the album is removed.
    /// </summary>
    public string? AlbumId { get; set; }

    /// <summary>
    /// Discogs' "M:SS" text, usually filled by picking a track from the linked album's tracklist (see <see cref="ReferenceTrackModel.Duration"/>) rather than typed.
    /// </summary>
    public string? Duration { get; set; }

    /// <summary>
    /// The <see cref="ReferenceTrackModel.Position"/> this song was created from.
    /// With <see cref="AlbumId"/> it is a track-based song's identity, so picking the same track twice reuses the song (see <c>SongApiClient.GetOrCreateForTrackAsync</c>).
    /// Null for a song not tied to a specific tracklist entry.
    /// </summary>
    public string? TrackPosition { get; set; }
}
