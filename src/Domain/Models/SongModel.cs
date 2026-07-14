using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class SongModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public string? Artist { get; set; }

    /// <summary>
    /// Optional link to the tenant's own <see cref="AlbumModel.Id"/> - a soft reference, like
    /// <c>ReferenceId</c> elsewhere in the codebase: no cascade-delete or enforcement if the album is
    /// later removed.
    /// </summary>
    public string? AlbumId { get; set; }

    /// <summary>
    /// Discogs' own "M:SS" text, usually filled in by picking a track from the linked album's reference
    /// tracklist (see <see cref="ReferenceTrackModel.Duration"/>) rather than typed by hand.
    /// </summary>
    public string? Duration { get; set; }

    /// <summary>
    /// The <see cref="ReferenceTrackModel.Position"/> this song was created from - combined with
    /// <see cref="AlbumId"/>, this is a track-based song's real identity: picking the same track twice
    /// must reuse the same <see cref="SongModel"/>, not create a duplicate (see
    /// <c>SongApiClient.GetOrCreateForTrackAsync</c>). Null for a song not tied to a specific tracklist entry.
    /// </summary>
    public string? TrackPosition { get; set; }
}
