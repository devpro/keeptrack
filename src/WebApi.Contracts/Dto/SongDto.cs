using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Song data transfer object.
/// </summary>
public class SongDto : IHasId
{
    /// <summary>
    /// Song ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Song title.
    /// </summary>
    public string? Title { get; set; }

    public string? Artist { get; set; }

    /// <summary>
    /// Id of the tenant's own album this song is from, if any, not a reference document.
    /// </summary>
    public string? AlbumId { get; set; }

    public string? Duration { get; set; }

    /// <summary>
    /// The tracklist position this song was created from.
    /// With <see cref="AlbumId"/>, it lets the client reuse the song already created for an album track rather than create a duplicate.
    /// </summary>
    public string? TrackPosition { get; set; }
}
