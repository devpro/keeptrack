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
    /// Id of the linked <c>Album</c> this song is from, if any - the tenant's own tracked album, not
    /// external reference-data.
    /// </summary>
    public string? AlbumId { get; set; }

    public string? Duration { get; set; }

    /// <summary>
    /// The reference tracklist position this song was created from - combined with <see cref="AlbumId"/>,
    /// lets the client look up (and reuse) the song already created for a given album track instead of
    /// creating a duplicate.
    /// </summary>
    public string? TrackPosition { get; set; }
}
